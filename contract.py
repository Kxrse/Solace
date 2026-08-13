"""
Maps an accessor or method name in plugin source back to the symbol string AsaApi
looks up at runtime

Without this you can only check source against SetHook literals
Unchanged from the bot apart from these comments
"""

import os
import re

# Line by line, no real parser, the headers are generated and keep a rigid shape so this
# holds. Does mean a formatting change upstream quietly loses coverage instead of failing
# loud
STRUCT_PATTERN = re.compile(r"^\s*struct\s+([A-Za-z_]\w*)\s*(?::\s*([A-Za-z_][\w:<>,\s]*?))?\s*\{?\s*$")
NATIVE_KEY_PATTERN = re.compile(r"NativeCall<[^;]*?>\(\s*(?:this|nullptr)\s*,\s*\"([^\"]+)\"")
FIELD_PATTERN = re.compile(r"\b([A-Za-z_]\w*)\s*\(\s*\)\s*(?:const\s*)?\{.*GetNativePointerField<.*>\(\s*this\s*,\s*\"([^\"]+)\"")
BITFIELD_PATTERN = re.compile(r"BitFieldValue<[^>]*>\s+(\w+)\s*\(\s*\)\s*(?:const\s*)?\{\s*return\s*\{\s*this\s*,\s*\"([^\"]+)\"")


class Contract:
    def __init__(self):
        self.methods = {}
        self.fields = {}
        self.bitfields = {}
        self.bases = {}
        self.method_key_index = {}
        self.field_accessor_index = {}
        self.bitfield_accessor_index = {}
        self.header_count = 0
        self.fingerprint = None
        self.header_dir = None

    @property
    def loaded(self):
        return self.header_count > 0

    def stats(self):
        return {
            "headers": self.header_count,
            "classes": len(self.bases),
            "native_calls": sum(len(keys) for cls in self.methods.values() for keys in cls.values()),
            "field_accessors": sum(len(cls) for cls in self.fields.values()),
            "bitfield_accessors": sum(len(cls) for cls in self.bitfields.values()),
        }

    # Walks the inheritance chain, and the seen guard isnt paranoia, a half parsed header
    # can hand you a class that lists itself as its own base
    def chain(self, cls):
        seen = []
        current = cls
        while current and current not in seen:
            seen.append(current)
            current = self.bases.get(current)
        return seen

    def resolve_member(self, cls, name):
        for ancestor in self.chain(cls):
            methods = self.methods.get(ancestor)
            if methods and name in methods:
                return "call", set(methods[name])
            fields = self.fields.get(ancestor)
            if fields and name in fields:
                return "field", {fields[name]}
            bitfields = self.bitfields.get(ancestor)
            if bitfields and name in bitfields:
                return "bitfield", {bitfields[name]}
        return None, None

    # Fallback when the receiver type is unknown, every symbol declaring this name across
    # every class, caller decides if thats good enough
    def candidates(self, name):
        if name in self.method_key_index:
            return "call", set(self.method_key_index[name])
        if name in self.field_accessor_index:
            return "field", set(self.field_accessor_index[name])
        if name in self.bitfield_accessor_index:
            return "bitfield", set(self.bitfield_accessor_index[name])
        return None, None


# Reparsing every header is slow so callers cache the Contract and only rebuild when this
# changes
def header_fingerprint(header_dir):
    if not header_dir or not os.path.isdir(header_dir):
        return None
    count = 0
    latest = 0.0
    total = 0
    for root, _, files in os.walk(header_dir):
        for name in files:
            if not name.endswith(".h"):
                continue
            path = os.path.join(root, name)
            try:
                stat = os.stat(path)
            except OSError:
                continue
            count += 1
            total += stat.st_size
            if stat.st_mtime > latest:
                latest = stat.st_mtime
    if count == 0:
        return None
    return (count, int(latest), total)


def parse_headers(header_dir):
    result = Contract()
    result.header_dir = header_dir
    if not header_dir or not os.path.isdir(header_dir):
        return result
    for root, _, files in os.walk(header_dir):
        for name in sorted(files):
            if not name.endswith(".h"):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    lines = handle.readlines()
            except OSError:
                continue
            result.header_count += 1
            current = None
            for line in lines:
                struct_match = STRUCT_PATTERN.match(line)
                if struct_match:
                    current = struct_match.group(1)
                    base_raw = struct_match.group(2)
                    base = None
                    if base_raw:
                        base = base_raw.split(",")[0].split("<")[0].strip()
                        base = base.split("::")[-1] if base else None
                    if current not in result.bases or result.bases.get(current) is None:
                        result.bases[current] = base
                    continue
                if current is None:
                    continue
                bit_match = BITFIELD_PATTERN.search(line)
                if bit_match:
                    accessor, key = bit_match.group(1), bit_match.group(2)
                    result.bitfields.setdefault(current, {})[accessor] = key
                    result.bitfield_accessor_index.setdefault(accessor, set()).add(key)
                    continue
                field_match = FIELD_PATTERN.search(line)
                if field_match:
                    accessor, key = field_match.group(1), field_match.group(2)
                    result.fields.setdefault(current, {})[accessor] = key
                    result.field_accessor_index.setdefault(accessor, set()).add(key)
                    continue
                if line.lstrip().startswith("//"):
                    continue
                native_match = NATIVE_KEY_PATTERN.search(line)
                if native_match:
                    key = native_match.group(1)
                    head = key.split("(", 1)[0]
                    key_class, _, method = head.rpartition(".")
                    if not method:
                        continue
                    owner = current or key_class
                    result.methods.setdefault(owner, {}).setdefault(method, set()).add(key)
                    if key_class and key_class != owner:
                        result.methods.setdefault(key_class, {}).setdefault(method, set()).add(key)
                    result.method_key_index.setdefault(method, set()).add(key)
    result.fingerprint = header_fingerprint(header_dir)
    return result