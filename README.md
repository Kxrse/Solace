# Solace

Watches for Ark server updates and tells you which of your plugins the new build just broke, straight to a discord webhook.

Every time Wildcard patches the server, symbols move, get renamed, or disappear. Your plugin still compiles and still loads, and then faults the first time it hits a call site that no longer exists. Solace catches that before your players do.

No bot, no database, nothing to pip install.

---

## How it works

Every cycle it does the same four things.

1. Runs steamcmd against your dump server, or skips this if you have not configured steamcmd
2. Hashes `ArkAscendedServer.exe`. That hash is the build id
3. If the hash changed, pulls the offset cache for that build from the cdn
4. Scans every `.cpp` in your plugin folder against that cache and posts the result

If the cdn has not published the cache for the new build yet you get a `cache not ready` line in the log and it tries again next cycle. State is only written after a report actually goes out, so nothing gets silently skipped.

---

## What it actually checks

**Hooks.** Every `SetHook("...")` literal in your source is looked up in the cache. Missing means that hook is gone and the plugin will fault.

**Symbols.** Every call site and `SomethingField()` accessor is resolved through the DevAPI headers back to the symbol string AsaApi looks up at runtime, then checked against the cache. This is the part that needs `devapi_header_directory` set. Without it, hooks still get checked and symbols get skipped.

**Call signatures.** Compared against the previous build. A parameter added or removed means your call site no longer matches.

**Field and bitfield offsets.** Reported for information only. These do not affect the verdict, because AsaApi resolves fields by name at runtime, so a layout shift costs you nothing.

### Verdicts

| Verdict | Title | Means |
| --- | --- | --- |
| `broken` | Action required | A hook or symbol is gone. That plugin will fault |
| `drift` | Signature change | A call signature changed. Check your call sites before compiling |
| `clean` | Build clean | Nothing to do |

There is a fourth report titled **Unverified calls**. That is still verdict `clean` for filtering purposes. It means a call could not be tied to one class, usually an accessor name that several classes declare where the receiver type could not be worked out from source. Some of those candidates are dead. It is not necessarily broken, it just needs eyes on it.

Worth knowing if you filter your webhook to `broken` and `drift` only, because you will not see those.

---

## Requirements

Python 3.9 or newer. That is it.

If you want it to update the server itself you need steamcmd, and a disk with room for a full server install, roughly 15gb. If you already run a server on that box, point it at the existing install and leave `steamcmd_path` blank instead.

---

## Setup

1. Unzip somewhere
2. Open `config.json` and fill in the paths
3. `python solace.py`

Leave it running. It will do nothing at all until Wildcard pushes an update, which is the point.

### config.json

**monitor**

| Key | Default | What it does |
| --- | --- | --- |
| `plugin_directory` | none, required | Folder of plugin source. Walked recursively |
| `server_directory` | `Server` next to the script | Where the server lives. steamcmd installs into this |
| `steamcmd_path` | blank | Path to steamcmd.exe. Leave blank to skip updating and just hash whatever exe is already there |
| `app_id` | `2430930` | Ark server app id. No reason to change it |
| `poll_seconds` | `300` | Cycle interval. Clamped to a minimum of 60 |
| `steamcmd_timeout_seconds` | `1800` | Kill steamcmd after this long |
| `rescan_on_source_change` | `true` | Also rescan when you edit a plugin, not just when the build changes |

**cache**

| Key | Default | What it does |
| --- | --- | --- |
| `cdn_url` | pelayori cache cdn | Where the offset caches come from |
| `devapi_header_directory` | blank | Your DevAPI header tree, the folder containing `API`. Blank means symbol checks are skipped |
| `work_directory` | `Work` next to the script | Staging area, and where `state.json` lives |
| `archive_directory` | `Archive` next to the script | Kept caches, one pair per build |
| `max_archive_builds` | `30` | How many builds to keep before pruning the oldest |
| `context_idle_seconds` | `600` | How long a parsed cache stays in memory before its dropped |

**report**

| Key | Default | What it does |
| --- | --- | --- |
| `webhook_username` | `Solace` | Name the webhook posts under |
| `webhook_avatar_url` | blank | Avatar the webhook posts with |
| `attach_full_report` | `true` | Attach the full txt when the report is too big for one embed |
| `report_directory` | `Reports` next to the script | Full report is always written here, whether its attached or not |

**webhooks**

A list, add as many as you want.

| Key | What it does |
| --- | --- |
| `name` | Label for the log line, not shown in discord |
| `url` | Your discord webhook url |
| `verdicts` | Which verdicts this webhook wants. Any of `clean`, `drift`, `broken` |
| `mention` | Posted as the message content, so `<@&roleid>` or `<@userid>`. Roles and users only, never everyone |

```json
"webhooks": [
  {
    "name": "urgent",
    "url": "https://discord.com/api/webhooks/...",
    "verdicts": [ "broken" ],
    "mention": "<@&123456789012345678>"
  },
  {
    "name": "everything",
    "url": "https://discord.com/api/webhooks/...",
    "verdicts": [ "clean", "drift", "broken" ],
    "mention": ""
  }
]
```

**logging**

| Key | Default | What it does |
| --- | --- | --- |
| `level` | `info` | `debug`, `info`, `warning` or `error` |
| `max_log_files` | `10` | Rotating logs in `Logs`, oldest deleted past this |

Config is hot reloadable. It gets rechecked every 10 seconds on size and last write time, and a half saved or broken json is ignored and the config already loaded stays live.

---

## Plugin folder layout

Recursive, no depth limit, and it only ever looks at `.cpp`. Zips are ignored.

The plugin name in the report comes off the first folder under `plugin_directory`.

```
Plugins\
  TurretFiller\
    TurretFiller\src\core\TurretFiller.cpp     ->  TurretFiller
  Kits\
    Kits.cpp                                   ->  Kits
```

Flat also works, the filename becomes the plugin name.

```
Plugins\
  TurretFiller.cpp                             ->  TurretFiller
```

Point it straight at your repo clone or your sln folder, either is fine.

One thing to watch. It grabs every `.cpp` in the tree, so vendored or third party source sitting inside a project folder gets scanned too and shows up as findings against that plugin.

---

## Commands

```
python solace.py
```

Runs the watcher until you ctrl c it. This is the normal way to use it.

```
python solace.py --scan
```

One shot against the latest archived build. Prints to console, writes the txt to your report folder, posts nothing to discord. Use this to check your setup, or after an edit when you cant be bothered waiting.

```
python solace.py --simulate broken
```

Fires a fake report at your webhooks so you can prove delivery works without waiting for a patch. Takes `clean`, `drift`, `broken` or `everything`.

Both `--scan` and `--simulate` need at least one archived build first, so let the watcher finish a cycle before you use them.

---

## Rescanning on edits

With `rescan_on_source_change` on, the watcher fingerprints your plugin folder every 10 seconds and rescans when something changes. It only posts if the findings actually differ, so touching a file with no real change logs `findings unchanged` and stays quiet.

The first pass after startup only sets the baseline, it will not fire a report just because you restarted it.

---

## state.json

Lives in your work folder and holds the last reported build hash, the signature of what was said about it, and the verdict.

Delete it and the next cycle treats the current build as new and reports again. That is the manual way to redeliver.

It will not refetch the archived cache though, since an existing archive file is never overwritten. If a cache got archived wrong you have to delete it from the archive folder as well.

---

## Gotchas

**No baseline on the first build.** Drift is a comparison, so the first build Solace ever sees has nothing to compare to. Hooks and symbols still get checked. Second build onward you get everything.

**Symbols skipped.** `devapi_header_directory` is not set, or points at the wrong level. It wants the folder holding `API`.

**cache not ready.** The cdn has not cooked the cache for that build yet. Normal after a fresh patch, it retries every cycle.

**steamcmd manifest is still wedged.** steamcmd left the install half done. Solace already deletes the manifest and retries once by itself. If it says this, go clear it by hand.

**A short poll is expensive.** The cost is the steamcmd run, not the web request. 300 seconds is already plenty.

---

## Want more

This is the stripped down version. The full Solace bot does per user uploads, symbol lookup, forced cache refetches and delivery straight to your dms.

---

## License

Kxrse ASA Plugins Non-Commercial License. Use it, change it, share it, credit me. No selling it.
