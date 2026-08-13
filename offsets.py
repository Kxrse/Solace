"""
Does the actual work, scrapes plugin source and checks it against the offset cache

No printing and no config in here, you hand it a folder and a BuildContext and it
hands back a SourceResult
"""

import glob
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
import zipfile

# These run on preprocessed source so comments and string literals and #if 0 blocks
# are already gone
HOOK_PATTERN = re.compile(r'SetHook\s*\(\s*"([^"]+)"')
FIELD_ACCESSOR_PATTERN = re.compile(r'\b([A-Za-z_]\w*Field)\s*\(\s*\)')
TYPED_DECL_PATTERN = re.compile(r'\b([AUF][A-Za-z0-9_]+)\s*[*&]\s*([A-Za-z_]\w*)\s*(?=[=;,)]|:(?!:))')
CAST_ASSIGN_PATTERN = re.compile(r'\b([A-Za-z_]\w*)\s*=\s*(?:static_cast|reinterpret_cast)<\s*([AUF][A-Za-z0-9_]+)\s*\*\s*>')
ARROW_CALL_PATTERN = re.compile(r'\b([A-Za-z_]\w*)\s*(->|\.)\s*([A-Za-z_]\w*)\s*\(')
SCOPE_CALL_PATTERN = re.compile(r'\b([A-Za-z_]\w*)\s*::\s*([A-Za-z_]\w*)\s*\(')
IDENTIFIER_PATTERN = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
ADJACENT_STRINGS_PATTERN = re.compile(r'"\s*\n?\s*"')
STATE_FLAGS_PATTERN = re.compile(r'"StateFlags"\s*"(\d+)"')

# Cache format is little endian, 8 byte name length then the name then the value
# Offsets get an 8 byte address and bitfields get a 32 byte trailer
BITFIELD_TRAILER = 32
SOURCE_EXTENSIONS = (".cpp",)
STEAMCMD_READY_FLAGS = "4"

VERDICT_CLEAN = "clean"
VERDICT_DRIFT = "drift"
VERDICT_BROKEN = "broken"


class FileReport:
    def __init__(self, name, plugin):
        self.name = name
        self.plugin = plugin
        self.hook_count = 0
        self.missing_hooks = []
        self.symbol_count = 0
        self.missing_symbols = []
        self.unverified = []
        self.unresolved = 0
        self.field_drift = {}
        self.call_drift = {}
        self.bitfield_drift = {}

    @property
    def broken(self):
        return bool(self.missing_hooks) or bool(self.missing_symbols)

    @property
    def has_layout_shift(self):
        return bool(self.field_drift) or bool(self.bitfield_drift)

    @property
    def has_signature_change(self):
        return bool(self.call_drift)

    @property
    def needs_attention(self):
        return self.broken or self.has_signature_change or bool(self.unverified)


class SourceResult:
    def __init__(self, label):
        self.label = label
        self.files = []
        self.skipped_files = 0
        self.contract_loaded = False
        self.baseline_loaded = False
        self.bitfields_loaded = False

    @property
    def hook_count(self):
        return sum(report.hook_count for report in self.files)

    @property
    def symbol_count(self):
        return sum(report.symbol_count for report in self.files)

    @property
    def missing_hook_count(self):
        return sum(len(report.missing_hooks) for report in self.files)

    @property
    def missing_symbol_count(self):
        return sum(len(report.missing_symbols) for report in self.files)

    @property
    def unresolved_count(self):
        return sum(report.unresolved for report in self.files)

    @property
    def unverified_count(self):
        return sum(len(report.unverified) for report in self.files)

    @property
    def drift_counts(self):
        fields = sum(len(entries) for report in self.files for entries in report.field_drift.values())
        calls = sum(len(entries) for report in self.files for entries in report.call_drift.values())
        bits = sum(len(entries) for report in self.files for entries in report.bitfield_drift.values())
        return fields, calls, bits

    @property
    def plugin_total(self):
        return len(set(report.plugin for report in self.files))

    @property
    def plugin_attention_count(self):
        return len(set(report.plugin for report in self.files if report.needs_attention))

    # Field and bitfield moves dont change the verdict, AsaApi resolves those by name at
    # runtime so a layout shift is cosmetic. Only a symbol thats gone or a call signature
    # thats changed will actually break a build
    @property
    def verdict(self):
        if any(report.broken for report in self.files):
            return VERDICT_BROKEN
        if any(report.has_signature_change for report in self.files):
            return VERDICT_DRIFT
        return VERDICT_CLEAN

    def plugins(self):
        grouped = {}
        for report in self.files:
            grouped.setdefault(report.plugin, []).append(report)
        return dict(sorted(grouped.items()))

    def confidence_notes(self):
        notes = []
        if not self.contract_loaded:
            notes.append("symbol checks skipped, headers not loaded")
        elif self.unverified_count:
            notes.append("some calls could not be tied to a single symbol, see unverified")
        if not self.baseline_loaded:
            notes.append("drift skipped, no previous build")
        if not self.bitfields_loaded:
            notes.append("bitfield checks skipped, no bitfield cache")
        if self.skipped_files:
            notes.append(f"{self.skipped_files} files could not be read and were skipped")
        return notes

    def status_lines(self):
        if self.missing_hook_count:
            hooks = f"{self.hook_count} checked, {self.missing_hook_count} missing"
        else:
            hooks = f"{self.hook_count} checked, all resolve"
        if not self.contract_loaded:
            symbols = "skipped, no headers"
        elif self.missing_symbol_count:
            symbols = f"{self.symbol_count} checked, {self.missing_symbol_count} missing"
        else:
            symbols = f"{self.symbol_count} checked, all resolve"
        fields, calls, bits = self.drift_counts
        if not self.contract_loaded:
            unverified = "skipped, no headers"
        elif self.unverified_count:
            unverified = f"{self.unverified_count} could not be confirmed"
        else:
            unverified = "none"
        return [
            ("hooks", hooks),
            ("symbols", symbols),
            ("unverified", unverified),
            ("field offsets", describe_drift(self.baseline_loaded, fields, "moved")),
            ("call signatures", describe_drift(self.baseline_loaded, calls, "changed")),
            ("bitfields", describe_drift(self.baseline_loaded and self.bitfields_loaded, bits, "moved")),
        ]


def describe_drift(available, count, verb):
    if not available:
        return "skipped, no baseline"
    if not count:
        return "no change"
    return f"{count} {verb}"


def strip_comments(text):
    out = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == '"':
            out.append(char)
            index += 1
            while index < length:
                out.append(text[index])
                if text[index] == "\\":
                    index += 1
                    if index < length:
                        out.append(text[index])
                        index += 1
                    continue
                if text[index] == '"':
                    index += 1
                    break
                index += 1
            continue
        if char == "'":
            out.append(char)
            index += 1
            while index < length:
                out.append(text[index])
                if text[index] == "\\":
                    index += 1
                    if index < length:
                        out.append(text[index])
                        index += 1
                    continue
                if text[index] == "'":
                    index += 1
                    break
                index += 1
            continue
        if char == "/" and index + 1 < length:
            nxt = text[index + 1]
            if nxt == "/":
                while index < length and text[index] != "\n":
                    index += 1
                continue
            if nxt == "*":
                index += 2
                while index + 1 < length and not (text[index] == "*" and text[index + 1] == "/"):
                    if text[index] == "\n":
                        out.append("\n")
                    index += 1
                index += 2
                continue
        out.append(char)
        index += 1
    return "".join(out)


def strip_disabled_blocks(text):
    # Frames are [in_disabled_branch, dead, unused] and blank lines go back in where lines
    # were stripped so the line count still lines up
    out = []
    stack = []
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("#if"):
            disabled = bool(re.match(r'#if\s+0\b', stripped))
            parent_dead = bool(stack and stack[-1][1])
            stack.append([disabled, disabled or parent_dead, False])
            out.append("")
            continue
        if stripped.startswith("#else") or stripped.startswith("#elif"):
            if stack:
                frame = stack[-1]
                parent_dead = bool(len(stack) > 1 and stack[-2][1])
                if frame[0]:
                    frame[1] = parent_dead
                    frame[0] = False
                elif stripped.startswith("#else"):
                    frame[1] = True
            out.append("")
            continue
        if stripped.startswith("#endif"):
            if stack:
                stack.pop()
            out.append("")
            continue
        if stack and stack[-1][1]:
            out.append("")
            continue
        out.append(line)
    return "\n".join(out)


def preprocess_source(text):
    text = strip_comments(text)
    text = strip_disabled_blocks(text)
    text = ADJACENT_STRINGS_PATTERN.sub("", text)
    return text


def plugin_of(relative_path):
    parts = relative_path.split("/")
    if len(parts) > 1:
        return parts[0]
    return os.path.splitext(parts[0])[0]


class FileSource:
    def __init__(self, relative_path, text):
        self.name = relative_path
        self.plugin = plugin_of(relative_path)
        processed = preprocess_source(text)
        self.tokens = set(IDENTIFIER_PATTERN.findall(processed))
        self.hooks = set(HOOK_PATTERN.findall(processed))
        self.field_accessors = set(FIELD_ACCESSOR_PATTERN.findall(processed))
        # Best effort, if a receiver cant be typed the call falls through to the ambiguous
        # path in check_symbols instead of getting dropped
        var_types = {}
        for match in TYPED_DECL_PATTERN.finditer(processed):
            var_types[match.group(2)] = match.group(1)
        for match in CAST_ASSIGN_PATTERN.finditer(processed):
            var_types[match.group(1)] = match.group(2)
        self.calls = []
        for match in ARROW_CALL_PATTERN.finditer(processed):
            receiver, method = match.group(1), match.group(3)
            self.calls.append((var_types.get(receiver), method))
        for match in SCOPE_CALL_PATTERN.finditer(processed):
            self.calls.append((match.group(1), match.group(2)))
        self.call_names = {method for _, method in self.calls}
        self.hook_methods = {hook.split("(", 1)[0].rpartition(".")[2] for hook in self.hooks}
        self.text = processed


def collect_source_files(source_dir):
    found = []
    for root, _, files in os.walk(source_dir):
        for name in sorted(files):
            if not name.endswith(SOURCE_EXTENSIONS):
                continue
            path = os.path.join(root, name)
            relative = os.path.relpath(path, source_dir).replace(os.sep, "/")
            found.append((relative, path))
    return sorted(found)


def scrape_sources(source_dir):
    sources = []
    skipped = 0
    for relative, path in collect_source_files(source_dir):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError:
            skipped += 1
            continue
        sources.append(FileSource(relative, text))
    return sources, skipped


# Not a hash, just file count and newest mtime and total size, enough to notice an edit
# without reading every file every 10 seconds
def source_fingerprint(source_dir):
    if not source_dir or not os.path.isdir(source_dir):
        return None
    count = 0
    latest = 0.0
    total = 0
    for root, _, files in os.walk(source_dir):
        for name in files:
            if not name.endswith(SOURCE_EXTENSIONS):
                continue
            try:
                stat = os.stat(os.path.join(root, name))
            except OSError:
                continue
            count += 1
            total += stat.st_size
            if stat.st_mtime > latest:
                latest = stat.st_mtime
    if count == 0:
        return None
    return [count, int(latest), total]


def load_offsets(cache_path):
    with open(cache_path, "rb") as handle:
        data = handle.read()
    offsets = {}
    index = 0
    total = len(data)
    while index + 8 <= total:
        name_len = int.from_bytes(data[index:index + 8], "little")
        index += 8
        if name_len == 0 or index + name_len + 8 > total:
            raise ValueError(f"unexpected offsets format at byte {index - 8}")
        name = data[index:index + name_len].decode("ascii", "replace")
        index += name_len
        offsets[name] = int.from_bytes(data[index:index + 8], "little")
        index += 8
    if index != total:
        raise ValueError(f"trailing bytes in offsets, consumed {index} of {total}")
    return offsets


def load_bitfields(cache_path):
    with open(cache_path, "rb") as handle:
        data = handle.read()
    bitfields = {}
    index = 0
    total = len(data)
    while index + 8 <= total:
        name_len = int.from_bytes(data[index:index + 8], "little")
        index += 8
        if name_len == 0 or index + name_len + BITFIELD_TRAILER > total:
            raise ValueError(f"unexpected bitfield format at byte {index - 8}")
        name = data[index:index + name_len].decode("ascii", "replace")
        index += name_len
        bitfields[name] = data[index:index + BITFIELD_TRAILER]
        index += BITFIELD_TRAILER
    if index != total:
        raise ValueError(f"trailing bytes in bitfields, consumed {index} of {total}")
    return bitfields


def bitfield_position(trailer):
    offset = int.from_bytes(trailer[0:8], "little")
    bit = int.from_bytes(trailer[8:12], "little")
    return offset, bit


# _Parms entries are generated parameter structs and not call sites so they never count
def field_key_index(offsets):
    index = {}
    for name in offsets:
        if "(" in name or "_Parms" in name or "." not in name:
            continue
        _, _, field = name.rpartition(".")
        index.setdefault(field, []).append(name)
    return index


def signature_map(offsets):
    signatures = {}
    for name in offsets:
        if "(" not in name or "_Parms" in name or "." not in name:
            continue
        head = name.split("(", 1)[0]
        class_part, _, func = head.rpartition(".")
        if not func:
            continue
        signatures.setdefault(func, {}).setdefault(class_part, set()).add(name)
    return signatures


class BuildContext:
    def __init__(self, exe_hash, offsets, bitfields, prev_offsets, prev_bitfields):
        self.exe_hash = exe_hash
        self.offsets = offsets
        self.bitfields = bitfields or {}
        self.prev_offsets = prev_offsets
        self.prev_bitfields = prev_bitfields
        self.field_index = field_key_index(offsets)
        self.signatures = signature_map(offsets)
        self.prev_signatures = signature_map(prev_offsets) if prev_offsets else None

    @property
    def has_baseline(self):
        return self.prev_offsets is not None

    @property
    def has_bitfields(self):
        return bool(self.bitfields)


# Plain class names get checked against the token set, templated or namespaced ones fall
# back to substring because they never survive tokenising
def mentions_class(class_part, tokens, text):
    if IDENTIFIER_PATTERN.fullmatch(class_part):
        return class_part in tokens
    return class_part in text


def check_symbols(report, source, context, contract):
    if contract is None or not contract.loaded:
        return
    seen = set()
    for receiver_type, method in source.calls:
        kind = None
        keys = None
        if receiver_type is not None:
            kind, keys = contract.resolve_member(receiver_type, method)
        if kind is None:
            kind, keys = contract.candidates(method)
            if kind is None:
                continue
            # No typed receiver here so the accessor got matched against every class that
            # declares it. If one candidate is live the call is fine, but when the dead ones
            # span multiple classes and no SetHook backs it up theres no way to prove which
            # one this call site meant, thats what unverified means
            table = context.bitfields if kind == "bitfield" else context.offsets
            live = any(key in table for key in keys)
            if live:
                dedupe = (kind, method, "live")
                if dedupe not in seen:
                    seen.add(dedupe)
                    report.symbol_count += 1
                    classes = {key.split("(", 1)[0].rpartition(".")[0] for key in keys}
                    ambiguous = len(classes) > 1
                    backstopped = method in source.hook_methods
                    dead = sorted(key for key in keys if key not in table)
                    if dead and ambiguous and receiver_type is None and not backstopped:
                        report.unresolved += 1
                        report.unverified.append((method, dead))
                continue
            dedupe = (kind, method, tuple(sorted(keys)))
            if dedupe in seen:
                continue
            seen.add(dedupe)
            report.symbol_count += 1
            if kind == "bitfield" and not context.has_bitfields:
                continue
            report.missing_symbols.extend(sorted(keys))
            continue
        dedupe = (kind, method, tuple(sorted(keys)))
        if dedupe in seen:
            continue
        seen.add(dedupe)
        report.symbol_count += 1
        if kind == "bitfield":
            if not context.has_bitfields:
                continue
            if not any(key in context.bitfields for key in keys):
                report.missing_symbols.extend(sorted(keys))
            continue
        if not any(key in context.offsets for key in keys):
            report.missing_symbols.extend(sorted(keys))
    for accessor in source.field_accessors:
        kind, keys = contract.candidates(accessor)
        if kind == "field":
            dedupe = ("field", accessor, tuple(sorted(keys)))
            if dedupe in seen:
                continue
            seen.add(dedupe)
            report.symbol_count += 1
            if not any(key in context.offsets for key in keys):
                report.missing_symbols.extend(sorted(keys))
        elif kind == "bitfield":
            dedupe = ("bitfield", accessor, tuple(sorted(keys)))
            if dedupe in seen:
                continue
            seen.add(dedupe)
            report.symbol_count += 1
            if context.has_bitfields and not any(key in context.bitfields for key in keys):
                report.missing_symbols.extend(sorted(keys))


def check_field_drift(report, source, context):
    for accessor in source.field_accessors:
        field = accessor[:-len("Field")]
        for name in context.field_index.get(field, []):
            class_part, _, _ = name.rpartition(".")
            old = context.prev_offsets.get(name)
            new = context.offsets[name]
            if old is None or old == new:
                continue
            if not mentions_class(class_part, source.tokens, source.text):
                continue
            report.field_drift.setdefault(field, []).append((name, old, new))


def check_call_drift(report, source, context):
    for func in source.call_names:
        new_classes = context.signatures.get(func)
        if not new_classes:
            continue
        prev_classes = context.prev_signatures.get(func, {}) if context.prev_signatures else {}
        for class_part, new_set in new_classes.items():
            if not mentions_class(class_part, source.tokens, source.text):
                continue
            prev_set = prev_classes.get(class_part)
            if prev_set is None or prev_set == new_set:
                continue
            removed = sorted(prev_set - new_set)
            added = sorted(new_set - prev_set)
            report.call_drift.setdefault(func, []).append((class_part, removed, added))


def check_bitfield_drift(report, source, context):
    names = source.field_accessors | source.call_names
    for name, new_trailer in context.bitfields.items():
        if "_Parms" in name or "." not in name:
            continue
        class_part, _, field = name.rpartition(".")
        if field not in names and field + "Field" not in names:
            continue
        prev_trailer = context.prev_bitfields.get(name) if context.prev_bitfields else None
        if prev_trailer is None or prev_trailer == new_trailer:
            continue
        if not mentions_class(class_part, source.tokens, source.text):
            continue
        report.bitfield_drift.setdefault(field, []).append(
            (name, bitfield_position(prev_trailer), bitfield_position(new_trailer))
        )


def evaluate_sources(label, sources, skipped, context, contract):
    result = SourceResult(label)
    result.skipped_files = skipped
    result.contract_loaded = contract is not None and contract.loaded
    result.baseline_loaded = context.has_baseline
    result.bitfields_loaded = context.has_bitfields
    for source in sources:
        report = FileReport(source.name, source.plugin)
        report.hook_count = len(source.hooks)
        for symbol in sorted(source.hooks):
            if symbol not in context.offsets:
                report.missing_hooks.append(symbol)
        check_symbols(report, source, context, contract)
        if context.has_baseline:
            check_field_drift(report, source, context)
            check_call_drift(report, source, context)
            if context.prev_bitfields is not None:
                check_bitfield_drift(report, source, context)
        result.files.append(report)
    return result


def evaluate_source(label, source_dir, context, contract):
    sources, skipped = scrape_sources(source_dir)
    return evaluate_sources(label, sources, skipped, context, contract)


def hash_executable(exe_path):
    digest = hashlib.sha256()
    with open(exe_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_path(install_dir, app_id):
    return os.path.join(install_dir, "steamapps", f"appmanifest_{app_id}.acf")


# StateFlags 4 means fully installed, anything else and steamcmd left the app half done
# and it will sit like that forever until you delete the manifest
def manifest_wedged(install_dir, app_id):
    path = manifest_path(install_dir, app_id)
    if not os.path.isfile(path):
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError:
        return False
    match = STATE_FLAGS_PATTERN.search(text)
    if not match:
        return False
    return match.group(1) != STEAMCMD_READY_FLAGS


def run_steamcmd_update(steamcmd_path, install_dir, app_id, timeout_seconds):
    command = [
        steamcmd_path,
        "+force_install_dir", install_dir,
        "+login", "anonymous",
        "+app_update", app_id,
        "+quit",
    ]
    try:
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_seconds)
        timed_out = False
    except subprocess.TimeoutExpired:
        timed_out = True
    if not timed_out and not manifest_wedged(install_dir, app_id):
        return None
    path = manifest_path(install_dir, app_id)
    try:
        os.remove(path)
    except OSError:
        pass
    try:
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return "steamcmd timed out twice, update abandoned this cycle"
    if manifest_wedged(install_dir, app_id):
        return "steamcmd manifest is still wedged after a retry"
    return "steamcmd manifest was wedged, cleared and retried"


def download_file(url, dest):
    request = urllib.request.Request(url, headers={"User-Agent": "Solace"})
    with urllib.request.urlopen(request) as response:
        with open(dest, "wb") as handle:
            shutil.copyfileobj(response, handle)


# Temp file then rename, otherwise a crash mid copy leaves a truncated cache that still
# parses fine and quietly fucks every comparison after it
def archive_file_atomic(source, exe_hash, suffix, archive_dir, overwrite=False):
    os.makedirs(archive_dir, exist_ok=True)
    dest = os.path.join(archive_dir, exe_hash + suffix)
    if os.path.isfile(dest) and not overwrite:
        return
    fd, temp_path = tempfile.mkstemp(dir=archive_dir, suffix=".tmp")
    os.close(fd)
    try:
        shutil.copyfile(source, temp_path)
        os.replace(temp_path, dest)
    finally:
        if os.path.isfile(temp_path):
            os.remove(temp_path)


def prune_archive(archive_dir, keep):
    if keep <= 0 or not os.path.isdir(archive_dir):
        return []
    builds = []
    for name in os.listdir(archive_dir):
        if not name.endswith(".cache"):
            continue
        path = os.path.join(archive_dir, name)
        builds.append((os.path.getmtime(path), name[:-len(".cache")]))
    builds.sort()
    removed = []
    while len(builds) > keep:
        _, build = builds.pop(0)
        for suffix in (".cache", ".bitfields"):
            path = os.path.join(archive_dir, build + suffix)
            try:
                os.remove(path)
            except OSError:
                continue
        removed.append(build)
    return removed


def fetch_caches(exe_hash, work_dir, archive_dir, cdn_url, overwrite=False):
    url = cdn_url.rstrip("/") + "/" + exe_hash + ".zip"
    os.makedirs(work_dir, exist_ok=True)
    staging = tempfile.mkdtemp(dir=work_dir)
    try:
        zip_path = os.path.join(staging, "cache.zip")
        try:
            download_file(url, zip_path)
        except urllib.error.HTTPError as error:
            # 404 just means the cache for this build isnt cooked yet, not an error, state
            # stays untouched and it tries again next cycle
            if error.code == 404:
                return None, None, "cache not ready"
            return None, None, f"download failed with status {error.code}"
        except urllib.error.URLError as error:
            return None, None, f"download failed: {error.reason}"
        extract_dir = os.path.join(staging, "extract")
        try:
            with zipfile.ZipFile(zip_path) as archive:
                archive.extractall(extract_dir)
        except zipfile.BadZipFile:
            return None, None, "cache archive is not a valid zip"
        offset_matches = glob.glob(os.path.join(extract_dir, "**", "cached_offsets.cache"), recursive=True)
        if not offset_matches:
            return None, None, "cached_offsets.cache missing from archive"
        try:
            offsets = load_offsets(offset_matches[0])
        except ValueError as error:
            return None, None, f"offsets cache failed to parse: {error}"
        bitfields = {}
        bitfield_matches = glob.glob(os.path.join(extract_dir, "**", "cached_bitfields.cache"), recursive=True)
        if bitfield_matches:
            try:
                bitfields = load_bitfields(bitfield_matches[0])
            except ValueError as error:
                return None, None, f"bitfields cache failed to parse: {error}"
        archive_file_atomic(offset_matches[0], exe_hash, ".cache", archive_dir, overwrite=overwrite)
        if bitfield_matches:
            archive_file_atomic(bitfield_matches[0], exe_hash, ".bitfields", archive_dir, overwrite=overwrite)
        return offsets, bitfields, None
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def load_archived(build_hash, archive_dir):
    if not build_hash:
        return None, None
    offsets_path = os.path.join(archive_dir, build_hash + ".cache")
    bitfields_path = os.path.join(archive_dir, build_hash + ".bitfields")
    offsets = None
    bitfields = None
    if os.path.isfile(offsets_path):
        offsets = load_offsets(offsets_path)
    if os.path.isfile(bitfields_path):
        bitfields = load_bitfields(bitfields_path)
    return offsets, bitfields


# Sorted by mtime never by name, build hashes have no order to them
def latest_builds(archive_dir):
    if not os.path.isdir(archive_dir):
        return None, None
    caches = []
    for name in os.listdir(archive_dir):
        if not name.endswith(".cache"):
            continue
        path = os.path.join(archive_dir, name)
        caches.append((os.path.getmtime(path), name[:-len(".cache")]))
    caches.sort()
    if not caches:
        return None, None
    current = caches[-1][1]
    previous = caches[-2][1] if len(caches) > 1 else None
    return current, previous
