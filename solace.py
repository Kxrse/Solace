"""
Entry point, owns the config and logging and state and the watch loop

One blocking process, no event loop and nothing outside the stdlib
The scanning lives in offsets.py and the formatting lives in report.py
"""

import argparse
import json
import logging
import os
import re
import sys
import time

import contract as contract_module
import offsets
import report as report_module

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(ROOT_DIR, "config.json")
LOGS_DIR = os.path.join(ROOT_DIR, "Logs")
LOG_PATTERN = re.compile(r"^Log_(\d{4})\.log$")
STATE_FILE = "state.json"
# Only file it ever reads out of the server install
EXE_RELATIVE = os.path.join("ShooterGame", "Binaries", "Win64", "ArkAscendedServer.exe")

DEFAULT_MAX_LOG_FILES = 10
DEFAULT_POLL_SECONDS = 300
DEFAULT_APP_ID = "2430930"
DEFAULT_CDN_URL = "https://cdn.pelayori.com/cache/"
DEFAULT_STEAMCMD_TIMEOUT = 1800
DEFAULT_ARCHIVE_KEEP = 30
DEFAULT_CONTEXT_IDLE_SECONDS = 600
MIN_POLL_SECONDS = 60
CONFIG_WATCH_SECONDS = 10

LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}


def rotate_logs(keep):
    os.makedirs(LOGS_DIR, exist_ok=True)
    numbers = []
    for name in os.listdir(LOGS_DIR):
        match = LOG_PATTERN.match(name)
        if match:
            numbers.append(int(match.group(1)))
    numbers.sort()
    while len(numbers) >= max(1, keep):
        oldest = numbers.pop(0)
        try:
            os.remove(os.path.join(LOGS_DIR, f"Log_{oldest:04d}.log"))
        except OSError:
            pass
    next_number = (numbers[-1] + 1) if numbers else 1
    path = os.path.join(LOGS_DIR, f"Log_{next_number:04d}.log")
    open(path, "a", encoding="utf-8").close()
    return path


def create_logger(name, log_path, level):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(LOG_LEVELS.get(str(level).lower(), logging.INFO))
    formatter = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    if log_path:
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    logger.propagate = False
    return logger


class Config:
    def __init__(self, path=CONFIG_PATH):
        self._path = path
        self._data = {}
        self._size = 0
        self._mtime = 0.0
        self.load()

    def load(self):
        with open(self._path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            raise ValueError("config root must be an object")
        stat = os.stat(self._path)
        self._data = data
        self._size = stat.st_size
        self._mtime = stat.st_mtime

    def reload_if_changed(self):
        try:
            stat = os.stat(self._path)
        except OSError:
            return False
        # Zero bytes means an editor is mid save and not an empty config, and any parse
        # failure below just keeps the config thats already loaded
        if stat.st_size == 0:
            return False
        if stat.st_size == self._size and stat.st_mtime == self._mtime:
            return False
        try:
            self.load()
        except (OSError, ValueError):
            return False
        return True

    def section(self, name):
        value = self._data.get(name, {})
        return value if isinstance(value, dict) else {}

    def get(self, section, key, default=None):
        value = self.section(section).get(key, default)
        return default if value is None else value

    def webhooks(self):
        value = self._data.get("webhooks", [])
        return value if isinstance(value, list) else []


class Runtime:
    def __init__(self, config, log):
        self.config = config
        self.log = log
        self.contract = None
        self.contract_fingerprint = None
        self.source_fingerprint = None
        self.context = None
        self.context_key = None
        self.context_used = 0.0

    # A parsed offset cache is big and rebuilding it takes seconds, so current and previous
    # get held between scans and dropped once it goes idle
    def set_context(self, key, context):
        self.context = context
        self.context_key = key
        self.context_used = time.monotonic()

    def release_context(self):
        self.context = None
        self.context_key = None
        self.log.info("Released build context after idle timeout")

    def get_contract(self, header_dir):
        fingerprint = contract_module.header_fingerprint(header_dir)
        if fingerprint is None:
            self.contract = None
            self.contract_fingerprint = None
            return None
        if self.contract is not None and self.contract_fingerprint == fingerprint:
            return self.contract
        self.contract = contract_module.parse_headers(header_dir)
        self.contract_fingerprint = fingerprint
        stats = self.contract.stats()
        self.log.info(
            f"Contract loaded, {stats['headers']} headers, {stats['native_calls']} calls, "
            f"{stats['field_accessors']} fields, {stats['bitfield_accessors']} bitfields"
        )
        return self.contract


def resolve_paths(config):
    return {
        "plugin_dir": str(config.get("monitor", "plugin_directory", "") or ""),
        "server_dir": str(config.get("monitor", "server_directory", "") or os.path.join(ROOT_DIR, "Server")),
        "steamcmd": str(config.get("monitor", "steamcmd_path", "") or ""),
        "work_dir": str(config.get("cache", "work_directory", "") or os.path.join(ROOT_DIR, "Work")),
        "archive_dir": str(config.get("cache", "archive_directory", "") or os.path.join(ROOT_DIR, "Archive")),
        "report_dir": str(config.get("report", "report_directory", "") or os.path.join(ROOT_DIR, "Reports")),
        "header_dir": str(config.get("cache", "devapi_header_directory", "") or ""),
    }


def state_path(work_dir):
    return os.path.join(work_dir, STATE_FILE)


# Survives restarts, tracks which build got reported and what was said about it
# Delete this file and the current build reports again
def load_state(work_dir):
    path = state_path(work_dir)
    if not os.path.isfile(path):
        return {"build_hash": "", "signature": "", "verdict": ""}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {"build_hash": "", "signature": "", "verdict": ""}
    if not isinstance(data, dict):
        return {"build_hash": "", "signature": "", "verdict": ""}
    return {
        "build_hash": str(data.get("build_hash", "") or ""),
        "signature": str(data.get("signature", "") or ""),
        "verdict": str(data.get("verdict", "") or ""),
    }


def save_state(work_dir, state):
    os.makedirs(work_dir, exist_ok=True)
    with open(state_path(work_dir), "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2)


def write_report_file(report_dir, exe_hash, result):
    os.makedirs(report_dir, exist_ok=True)
    path = os.path.join(report_dir, f"report_{exe_hash[:12]}.txt")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(report_module.full_report_text(exe_hash, result))
    return path


def load_context(runtime, paths, current, previous):
    key = (current, previous)
    if runtime.context is not None and runtime.context_key == key:
        runtime.context_used = time.monotonic()
        return runtime.context
    new_offsets, new_bitfields = offsets.load_archived(current, paths["archive_dir"])
    if new_offsets is None:
        raise ValueError(f"archived cache for {current} failed to load")
    prev_offsets, prev_bitfields = offsets.load_archived(previous, paths["archive_dir"])
    context = offsets.BuildContext(current, new_offsets, new_bitfields, prev_offsets, prev_bitfields)
    runtime.set_context(key, context)
    return context


def scan_with_context(runtime, paths, context, label):
    contract = runtime.get_contract(paths["header_dir"])
    return offsets.evaluate_source(label, paths["plugin_dir"], context, contract)


def deliver(runtime, paths, exe_hash, result, reason):
    settings = runtime.config.section("report")
    write_report_file(paths["report_dir"], exe_hash, result)
    delivered = report_module.deliver_report(
        settings, runtime.config.webhooks(), runtime.log, exe_hash, result, reason
    )
    if delivered == 0:
        runtime.log.warning("No webhook accepted the report")
    return delivered


def run_cycle(runtime):
    paths = resolve_paths(runtime.config)
    if not os.path.isdir(paths["plugin_dir"]):
        runtime.log.error("plugin_directory is not a folder, nothing to monitor")
        return
    app_id = str(runtime.config.get("monitor", "app_id", DEFAULT_APP_ID))
    timeout_seconds = int(runtime.config.get("monitor", "steamcmd_timeout_seconds", DEFAULT_STEAMCMD_TIMEOUT))

    if paths["steamcmd"]:
        if not os.path.isfile(paths["steamcmd"]):
            runtime.log.error("steamcmd_path is set but the executable is missing")
            return
        note = offsets.run_steamcmd_update(paths["steamcmd"], paths["server_dir"], app_id, timeout_seconds)
        if note:
            runtime.log.warning(note)
            if "abandoned" in note or "still wedged" in note:
                return

    exe_path = os.path.join(paths["server_dir"], EXE_RELATIVE)
    if not os.path.isfile(exe_path):
        runtime.log.error(f"Server exe missing: {exe_path}")
        return

    # The exe hash is the build id, and its also what the cdn publishes under, so hashing
    # covers the change check and the fetch
    exe_hash = offsets.hash_executable(exe_path)
    state = load_state(paths["work_dir"])
    if exe_hash == state["build_hash"]:
        return

    runtime.log.info(f"Processing build {exe_hash}")
    cdn_url = str(runtime.config.get("cache", "cdn_url", DEFAULT_CDN_URL))
    new_offsets, new_bitfields, error = offsets.fetch_caches(
        exe_hash, paths["work_dir"], paths["archive_dir"], cdn_url
    )
    # State only moves after a report actually goes out, so a cache thats not up yet or a
    # delivery that failed gets retried next cycle instead of being skipped
    if error:
        runtime.log.info(f"{error} for {exe_hash}")
        return

    prev_offsets, prev_bitfields = offsets.load_archived(state["build_hash"], paths["archive_dir"])
    context = offsets.BuildContext(exe_hash, new_offsets, new_bitfields, prev_offsets, prev_bitfields)
    runtime.set_context((exe_hash, state["build_hash"]), context)
    result = scan_with_context(runtime, paths, context, "build")
    deliver(runtime, paths, exe_hash, result, "new build")

    state["build_hash"] = exe_hash
    state["signature"] = report_module.result_signature(result)
    state["verdict"] = result.verdict
    save_state(paths["work_dir"], state)
    runtime.source_fingerprint = offsets.source_fingerprint(paths["plugin_dir"])

    keep = int(runtime.config.get("cache", "max_archive_builds", DEFAULT_ARCHIVE_KEEP))
    pruned = offsets.prune_archive(paths["archive_dir"], keep)
    if pruned:
        runtime.log.info(f"Pruned {report_module.plural(len(pruned), 'archived build')}")


def check_source_change(runtime):
    paths = resolve_paths(runtime.config)
    fingerprint = offsets.source_fingerprint(paths["plugin_dir"])
    if fingerprint is None:
        return
    # First pass after startup only sets the baseline, otherwise this fires on every single
    # restart whether anything changed or not
    if runtime.source_fingerprint is None:
        runtime.source_fingerprint = fingerprint
        return
    if fingerprint == runtime.source_fingerprint:
        return
    runtime.source_fingerprint = fingerprint

    current, previous = offsets.latest_builds(paths["archive_dir"])
    if current is None:
        return
    context = load_context(runtime, paths, current, previous)
    result = scan_with_context(runtime, paths, context, "source")
    signature = report_module.result_signature(result)
    state = load_state(paths["work_dir"])
    if signature == state["signature"]:
        runtime.log.info("Source changed, findings unchanged")
        return
    runtime.log.info("Source changed, findings differ")
    deliver(runtime, paths, current, result, "source change")
    state["signature"] = signature
    state["verdict"] = result.verdict
    save_state(paths["work_dir"], state)


def watch(runtime):
    # Clamped because the real cost of a short poll is a steamcmd run, not the web request
    poll_seconds = max(MIN_POLL_SECONDS, int(runtime.config.get("monitor", "poll_seconds", DEFAULT_POLL_SECONDS)))
    runtime.log.info(f"Solace watching, polling every {poll_seconds} seconds")
    next_cycle = 0.0
    while True:
        if runtime.config.reload_if_changed():
            runtime.log.info("Config reloaded")
            poll_seconds = max(
                MIN_POLL_SECONDS, int(runtime.config.get("monitor", "poll_seconds", DEFAULT_POLL_SECONDS))
            )
        if time.monotonic() >= next_cycle:
            try:
                run_cycle(runtime)
            # Yes its broad, this is meant to sit running for months and one bad cycle
            # shouldnt take the watcher down with it
            except Exception as error:
                runtime.log.error(f"Cycle failed: {type(error).__name__}: {error}")
            next_cycle = time.monotonic() + poll_seconds
        if bool(runtime.config.get("monitor", "rescan_on_source_change", True)):
            try:
                check_source_change(runtime)
            except Exception as error:
                runtime.log.error(f"Source rescan failed: {type(error).__name__}: {error}")
        idle = int(runtime.config.get("cache", "context_idle_seconds", DEFAULT_CONTEXT_IDLE_SECONDS))
        if runtime.context is not None and time.monotonic() - runtime.context_used > idle:
            runtime.release_context()
        time.sleep(CONFIG_WATCH_SECONDS)


def run_scan(runtime):
    paths = resolve_paths(runtime.config)
    if not os.path.isdir(paths["plugin_dir"]):
        runtime.log.error("plugin_directory is not a folder, nothing to scan")
        return 1
    current, previous = offsets.latest_builds(paths["archive_dir"])
    if current is None:
        runtime.log.error("No archived build to check against, run the watcher once first")
        return 1
    context = load_context(runtime, paths, current, previous)
    result = scan_with_context(runtime, paths, context, "scan")
    path = write_report_file(paths["report_dir"], current, result)
    sys.stdout.write(report_module.full_report_text(current, result))
    runtime.log.info(f"Report written to {path}")
    return 0


def run_simulate(runtime, state):
    paths = resolve_paths(runtime.config)
    result = report_module.sample_result(state)
    exe_hash = "b17fedc6e6ab" + "0" * 52
    delivered = deliver(runtime, paths, exe_hash, result, f"simulated {state}")
    runtime.log.info(f"Simulated {state} report sent to {report_module.plural(delivered, 'webhook')}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Solace, Ark build symbol monitor")
    parser.add_argument("--scan", action="store_true", help="scan once against the latest archived build and print")
    parser.add_argument("--simulate", choices=["clean", "drift", "broken", "everything"], help="send a sample report")
    args = parser.parse_args()

    try:
        config = Config()
    except (OSError, ValueError) as error:
        sys.stderr.write(f"config.json could not be read: {error}\n")
        return 1

    keep = int(config.get("logging", "max_log_files", DEFAULT_MAX_LOG_FILES))
    log_path = rotate_logs(keep)
    log = create_logger("Solace", log_path, config.get("logging", "level", "info"))
    runtime = Runtime(config, log)

    if args.simulate:
        return run_simulate(runtime, args.simulate)
    if args.scan:
        return run_scan(runtime)
    try:
        watch(runtime)
    except KeyboardInterrupt:
        log.info("Stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
