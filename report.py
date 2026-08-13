"""
Formats the verdict and pushes it to discord

Kept identical to the bot so a report reads the same either way, and its all stdlib
urllib on purpose so theres nothing to pip install
"""

import datetime
import hashlib
import json
import time
import urllib.error
import urllib.request
import uuid

import offsets

COLOR_SUCCESS = 0x2ECC71
COLOR_WARNING = 0xE67E22
COLOR_ERROR = 0xE74C3C
COLOR_NEUTRAL = 0x5A6673

VERDICT_TITLES = {
    offsets.VERDICT_CLEAN: "Build clean",
    offsets.VERDICT_DRIFT: "Signature change",
    offsets.VERDICT_BROKEN: "Action required",
}

VERDICT_COLORS = {
    offsets.VERDICT_CLEAN: COLOR_SUCCESS,
    offsets.VERDICT_DRIFT: COLOR_WARNING,
    offsets.VERDICT_BROKEN: COLOR_ERROR,
}

ALL_VERDICTS = (offsets.VERDICT_CLEAN, offsets.VERDICT_DRIFT, offsets.VERDICT_BROKEN)

STATUS_LABELS = [
    ("Hooks", "hooks"),
    ("Symbols", "symbols"),
    ("Unverified", "unverified"),
    ("Field offsets", "field offsets"),
    ("Call signatures", "call signatures"),
    ("Bitfields", "bitfields"),
]

UNVERIFIED_TITLE = "Unverified calls"

# discord allows 25 fields and 1024 chars a field and 6000 chars an embed
# These sit under all three so a big report turns into an attachment instead of getting
# rejected outright
MAX_FIELDS = 18
MAX_FIELD_CHARS = 1000
MAX_EMBED_CHARS = 5200
WEBHOOK_ATTEMPTS = 3
WEBHOOK_TIMEOUT = 30
RETRY_CAP_SECONDS = 60


def plural(count, word):
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def build_tally(result):
    total = result.plugin_total
    affected = result.plugin_attention_count
    if not total:
        return "no plugins"
    if affected:
        return f"{affected}/{total} plugins affected"
    return f"{total}/{total} plugins clean"


def build_summary(result):
    broken_hooks = result.missing_hook_count
    broken_symbols = result.missing_symbol_count
    fields, calls, bits = result.drift_counts
    moved = fields + bits

    if broken_hooks or broken_symbols:
        parts = []
        if broken_hooks:
            parts.append(plural(broken_hooks, "hook"))
        if broken_symbols:
            parts.append(plural(broken_symbols, "symbol"))
        lines = [
            f"**{' and '.join(parts)} no longer exist in this build.**",
            "Affected plugins will fault until they are updated.",
        ]
        if calls:
            lines.append("Call signatures changed as well, see the details below.")
    elif calls:
        lines = [
            f"**{plural(calls, 'call signature')} changed in this build.**",
            "Check the affected call sites before compiling against this build.",
        ]
    elif result.unverified_count:
        lines = [
            "**Nothing broken was found, but some calls could not be confirmed.**",
            "Check the unverified entries below by hand.",
        ]
    elif moved:
        lines = [
            "**Everything checks out.**",
            "The binary layout shifted but offsets resolve at runtime, so no action is needed.",
        ]
    else:
        lines = [
            "**Everything checks out.**",
            "No action needed for this build.",
        ]
    lines.append(build_tally(result))
    return "\n".join(lines)


def chunk_field(lines):
    value = ""
    for line in lines:
        if len(value) + len(line) + 1 > MAX_FIELD_CHARS:
            value += "..."
            break
        value += line + "\n"
    return value.rstrip() or "none"


def plugin_lines(reports):
    lines = []
    for report in reports:
        header_bits = []
        if report.missing_hooks:
            header_bits.append(plural(len(report.missing_hooks), "missing hook"))
        if report.missing_symbols:
            header_bits.append(plural(len(report.missing_symbols), "missing symbol"))
        call_changes = sum(len(v) for v in report.call_drift.values())
        if call_changes:
            header_bits.append(plural(call_changes, "signature change"))
        if report.unverified:
            header_bits.append(f"{len(report.unverified)} unverified")
        if not header_bits:
            continue
        lines.append(f"**{report.name}**, {', '.join(header_bits)}")
        for symbol in sorted(set(report.missing_hooks)):
            lines.append(f"missing hook `{symbol}`")
        for symbol in sorted(set(report.missing_symbols)):
            lines.append(f"missing `{symbol}`")
        for method, dead in sorted(report.unverified):
            if dead:
                lines.append(f"unverified `{method}`, dead on {', '.join(f'`{key}`' for key in dead)}")
            else:
                lines.append(f"unverified `{method}`, could not tie to one class")
        for func in sorted(report.call_drift):
            for class_part, removed, added in sorted(report.call_drift[func]):
                for symbol in removed:
                    lines.append(f"was `{symbol}`")
                for symbol in added:
                    lines.append(f"now `{symbol}`")
        lines.append("")
    return lines


def detail_fields(result):
    fields = []
    for plugin, reports in result.plugins().items():
        lines = plugin_lines(reports)
        if lines:
            fields.append((plugin, lines))
    return fields


def full_report_text(exe_hash, result):
    lines = [f"Build {exe_hash}", ""]
    for label, value in result.status_lines():
        lines.append(f"{label}: {value}")
    notes = result.confidence_notes()
    if notes:
        lines.append("")
        for note in notes:
            lines.append(f"note: {note}")
    for plugin, reports in result.plugins().items():
        block = plugin_lines(reports)
        if not block:
            continue
        lines.append("")
        lines.append(f"== {plugin} ==")
        for line in block:
            lines.append(line.replace("**", "").replace("`", ""))
    return "\n".join(lines).rstrip() + "\n"


# Identity of the findings, used so the same problem doesnt get posted twice
# Field and bitfield drift are left out on purpose, a layout shift that changes nothing
# for the plugin shouldnt fire another report
def result_signature(result):
    parts = []
    for report in sorted(result.files, key=lambda entry: entry.name):
        for symbol in sorted(set(report.missing_hooks)):
            parts.append(f"hook|{report.name}|{symbol}")
        for symbol in sorted(set(report.missing_symbols)):
            parts.append(f"symbol|{report.name}|{symbol}")
        for method, dead in sorted(report.unverified):
            parts.append(f"unverified|{report.name}|{method}|{','.join(dead)}")
        for func in sorted(report.call_drift):
            for class_part, removed, added in sorted(report.call_drift[func]):
                parts.append(
                    f"call|{report.name}|{func}|{class_part}|{','.join(removed)}|{','.join(added)}"
                )
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def build_embed(exe_hash, result, reason):
    description = build_summary(result)
    title = VERDICT_TITLES[result.verdict]
    color = VERDICT_COLORS[result.verdict]
    if result.verdict == offsets.VERDICT_CLEAN and result.unverified_count:
        title = UNVERIFIED_TITLE
        color = COLOR_NEUTRAL

    statuses = dict(result.status_lines())
    checks = "\n".join(f"{label}: {statuses[key]}" for label, key in STATUS_LABELS)
    embed_fields = [{"name": "Checks", "value": checks, "inline": False}]

    # Same maths the bot uses, dont fix this to subtract the Checks field too or reports
    # will truncate earlier here then they do there
    budget = MAX_EMBED_CHARS - len(description) - len(title)
    fields = detail_fields(result)
    shown = 0
    overflow = False
    for name, lines in fields:
        value = chunk_field(lines)
        cost = len(name) + len(value)
        if shown >= MAX_FIELDS or cost > budget:
            overflow = True
            break
        if value.endswith("..."):
            overflow = True
        embed_fields.append({"name": name[:256], "value": value, "inline": False})
        budget -= cost
        shown += 1
    if shown < len(fields):
        overflow = True

    footer_parts = [f"Build {exe_hash[:12]}"]
    if reason:
        footer_parts.append(reason)
    footer_parts.extend(result.confidence_notes())
    embed = {
        "title": title,
        "description": description,
        "color": color,
        "fields": embed_fields,
        "footer": {"text": " | ".join(footer_parts)[:2048]},
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    return embed, overflow


def post_webhook(url, payload, attachment=None):
    if attachment is None:
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "Solace"}
    else:
        # discord wants the embed as a payload_json part next to files[n] and not as its
        # own request, hand rolled because urllib has no multipart writer
        filename, data = attachment
        boundary = uuid.uuid4().hex
        segments = [
            f"--{boundary}\r\n".encode("utf-8"),
            b'Content-Disposition: form-data; name="payload_json"\r\n',
            b"Content-Type: application/json\r\n\r\n",
            json.dumps(payload).encode("utf-8"),
            f"\r\n--{boundary}\r\n".encode("utf-8"),
            f'Content-Disposition: form-data; name="files[0]"; filename="{filename}"\r\n'.encode("utf-8"),
            b"Content-Type: text/plain\r\n\r\n",
            data,
            f"\r\n--{boundary}--\r\n".encode("utf-8"),
        ]
        body = b"".join(segments)
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "Solace",
        }
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    for attempt in range(WEBHOOK_ATTEMPTS):
        try:
            with urllib.request.urlopen(request, timeout=WEBHOOK_TIMEOUT) as response:
                return response.status, None
        except urllib.error.HTTPError as error:
            # discord puts the wait in the Retry-After header, capped so a stupid value
            # cant park the whole loop
            if error.code == 429:
                delay = error.headers.get("Retry-After", "5")
                try:
                    wait = float(delay)
                except ValueError:
                    wait = 5.0
                time.sleep(min(wait, RETRY_CAP_SECONDS))
                continue
            if 500 <= error.code < 600:
                time.sleep(2.0 * (attempt + 1))
                continue
            return None, f"status {error.code}"
        except urllib.error.URLError:
            time.sleep(2.0 * (attempt + 1))
    return None, "webhook did not accept the report"


def deliver_report(settings, webhooks, log, exe_hash, result, reason):
    embed, overflow = build_embed(exe_hash, result, reason)
    attachment = None
    if overflow and bool(settings.get("attach_full_report", True)):
        text = full_report_text(exe_hash, result)
        attachment = (f"report_{exe_hash[:12]}.txt", text.encode("utf-8"))
    username = str(settings.get("webhook_username", "") or "Solace")
    avatar = str(settings.get("webhook_avatar_url", "") or "")
    delivered = 0
    for entry in webhooks:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name", "") or "webhook")
        url = str(entry.get("url", "") or "")
        if not url:
            continue
        verdicts = entry.get("verdicts") or list(ALL_VERDICTS)
        if result.verdict not in verdicts:
            continue
        # Roles and users only, never everyone, a webhook token is enough to ping an
        # entire server by accident
        payload = {
            "username": username,
            "embeds": [embed],
            "allowed_mentions": {"parse": ["roles", "users"]},
        }
        if avatar:
            payload["avatar_url"] = avatar
        mention = str(entry.get("mention", "") or "")
        if mention:
            payload["content"] = mention
        status, error = post_webhook(url, payload, attachment)
        if error:
            log.error(f"Webhook {name} failed, {error}")
            continue
        delivered += 1
        log.info(f"Webhook {name} accepted the report")
    return delivered


def sample_result(state):
    result = offsets.SourceResult("simulated")
    result.contract_loaded = True
    result.baseline_loaded = True
    result.bitfields_loaded = True
    report = offsets.FileReport("TurretFiller/TurretFiller.cpp", "TurretFiller")
    report.hook_count = 12
    report.symbol_count = 84
    second = offsets.FileReport("CloudStorage/CloudStorage.cpp", "CloudStorage")
    second.hook_count = 15
    second.symbol_count = 61
    second.unverified = [("GetPlayerName", ["AShooterPlayerState.GetPlayerName()"])]

    if state in ("broken", "everything"):
        report.missing_hooks = [
            "APrimalStructureTurret.RemoteInventoryAllowRemoveItems(AShooterPlayerController*)",
        ]
        second.missing_symbols = [
            "UPrimalInventoryComponent.AddNewItem(TSubclassOf<UPrimalItem>,bool,bool,float)",
        ]

    if state in ("drift", "everything"):
        report.field_drift = {
            "DescriptiveNameBase": [("UPrimalItem.DescriptiveNameBase", 0x5B0, 0x590)],
        }
        second.call_drift = {
            "ProcessConsoleExec": [
                (
                    "AShooterPlayerController",
                    ["AShooterPlayerController.ProcessConsoleExec(wchar_t*,FOutputDevice*,UObject*)"],
                    ["AShooterPlayerController.ProcessConsoleExec(wchar_t*,FOutputDevice*,UObject*,bool)"],
                )
            ]
        }
        second.bitfield_drift = {
            "bIsSleeping": [("AShooterCharacter.bIsSleeping", (0xA10, 3), (0xA10, 4))]
        }

    result.files = [report, second]
    return result
