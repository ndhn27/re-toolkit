"""
il2cpp_names.py

Looking a method up BY NAME instead of by address - the Python half of the
"name first, address as the fallback" mode (the agents' half is scripts/_resolve.js).

Two jobs:

  1. A NAME SPEC says which method is meant: `Namespace.Class::Method`, optionally
     `/N` for "the overload with N parameters" and `Outer/Inner` for a nested class:

         ExampleNamespace.ExampleTableA::Unpack            any overload (refused if there is more than one)
         ExampleNamespace.ExampleTableA::Unpack/1          the one-parameter overload
         ExampleNamespace.ExampleOuter/ExampleInner::Run   a nested class

     In a profile a spec may also be an object - `{"class": "...", "method": "...", "args": 1,
     "assembly": "Assembly-CSharp"}` - which is the only way to name the assembly (see
     profiles.py). `parse_method_spec()` reads both; it is the one definition of the
     grammar, and scripts/_resolve.js reads the parsed fields, not the text.

  2. A METADATA DUMP of a build lists every method with the RVA it was compiled to.
     `load_metadata()` reads what an IL2CPP dumper writes:

         script.json   Il2CppDumper's `ScriptMethod` list: {"Address": RVA, "Name":
                       "Ns.Class$$Method", "Signature": "...C signature..."}
         dump.cs       the `// RVA: 0x... Offset: 0x... VA: 0x...` comment in front of each method
         anything else a plain symbol map: one `NAME ADDRESS` (or `ADDRESS NAME`) per line,
                       NAME as `Ns.Class$$Method` or `Ns.Class::Method`, `#` starts a comment

     and `MethodIndex.lookup(spec)` answers with ONE entry or says why not: not in the dump,
     or more than one address (overloads the spec does not tell apart, or one name at two
     addresses). An ambiguous name is an error, never a pick - the point of looking a name
     up is that it is not a guess.

     What a name buys over a byte fingerprint (retk relocate): it survives a
     function that was REWRITTEN, which a fingerprint cannot find. What it does not buy: the
     dump must be of the same build as the binary it is applied to - relocate_offset.py
     checks the result against the binary (aligned, executable) and against the byte
     fingerprint when it has one.

Generic methods and generic classes are not covered: a shared generic body has no single
method pointer to find by name, and none of the three formats names an instantiation.
"""
import json
import re
from dataclasses import dataclass
from typing import Optional


class SpecError(ValueError):
    """A name spec that is not `Namespace.Class::Method[/N]` (or the object form)."""


class MetadataError(ValueError):
    """A metadata file that could not be read or has none of the expected content."""


class NameLookupError(LookupError):
    """A well-formed name that the metadata does not settle. `kind` is \"not_found\" or
    \"ambiguous\", `matches` the entries that were found (more than one when ambiguous)."""

    def __init__(self, message, kind, matches=()):
        super().__init__(message)
        self.kind = kind
        self.matches = tuple(matches)


# The IL2CPP C API functions scripts/_resolve.js may call, by their documented names. A
# profile's `names.exports` may say what the module really exports one of them as (a build that
# renames its exports); anything else is a typo. Keep equal to API_FUNCTIONS in
# scripts/_resolve.js (tests/test_names_agent.py checks they match).
API_FUNCTIONS = (
    "il2cpp_init", "il2cpp_init_utf16", "il2cpp_thread_attach",
    "il2cpp_domain_get", "il2cpp_domain_get_assemblies", "il2cpp_assembly_get_image",
    "il2cpp_image_get_name", "il2cpp_class_from_name", "il2cpp_class_get_name",
    "il2cpp_class_get_nested_types", "il2cpp_class_get_methods", "il2cpp_class_get_method_from_name",
    "il2cpp_method_get_name", "il2cpp_method_get_param_count",
    "il2cpp_class_get_field_from_name", "il2cpp_field_get_offset", "il2cpp_field_static_get_value",
)

# --------------------------------------------------------------------------------------
# name specs
# --------------------------------------------------------------------------------------

_IDENT = r"[A-Za-z_][A-Za-z0-9_`]*"
# A method name may be a constructor (.ctor / .cctor) or a compiler-generated name such as
# <Start>b__0_0, so it is only required to have no separator or whitespace in it.
_METHOD_RE = re.compile(r"^[^\s:/]+$")
_CLASS_RE = re.compile(rf"^(?:{_IDENT}\.)*{_IDENT}(?:/{_IDENT})*$")


@dataclass(frozen=True)
class MethodSpec:
    """One method, by name. `namespace` is "" for a global class; `cls` is the class name,
    `Outer/Inner` when nested. `argc` None means any - which a lookup refuses if that is
    more than one method."""
    namespace: str
    cls: str
    method: str
    argc: Optional[int] = None
    assembly: Optional[str] = None

    @property
    def qualified_class(self):
        """`Ns.Outer.Inner`: the form the dumpers print (a nested class is joined with '.')."""
        name = self.cls.replace("/", ".")
        return f"{self.namespace}.{name}" if self.namespace else name

    def __str__(self):
        text = f"{self.namespace + '.' if self.namespace else ''}{self.cls}::{self.method}"
        return text if self.argc is None else f"{text}/{self.argc}"

    def as_agent(self):
        """The fields scripts/_resolve.js takes (JSON-able; `args` -1 = any)."""
        out = {"namespace": self.namespace, "class": self.cls, "method": self.method,
               "args": -1 if self.argc is None else self.argc}
        if self.assembly:
            out["assembly"] = self.assembly
        return out


def _split_class(text, where):
    top, sep, nested = text.partition("/")
    if "." in top:
        namespace, _, name = top.rpartition(".")
    else:
        namespace, name = "", top
    cls = name + sep + nested
    if not _CLASS_RE.match(f"{namespace + '.' if namespace else ''}{cls}"):
        raise SpecError(f"{where}: {text!r} is not a class name "
                        f"(expected Namespace.Class or Namespace.Outer/Inner)")
    return namespace, cls


def parse_method_spec(value, where="name"):
    """A `MethodSpec` from `Ns.Class::Method[/N]` or from `{"class", "method", "args"?, "assembly"?}`.
    Raises SpecError, naming `where`, for anything else."""
    if isinstance(value, MethodSpec):
        return value
    if isinstance(value, dict):
        unknown = sorted(set(value) - {"class", "method", "args", "assembly"})
        if unknown:
            raise SpecError(f"{where}: unknown key(s) {', '.join(unknown)} "
                            f"(allowed: class, method, args, assembly)")
        for key in ("class", "method"):
            if not isinstance(value.get(key), str) or not value[key].strip():
                raise SpecError(f"{where}: `{key}` is required and must be a non-empty string")
        args = value.get("args")
        if args is not None and (isinstance(args, bool) or not isinstance(args, int) or args < 0):
            raise SpecError(f"{where}: `args` must be a parameter count (0 or more), got {args!r}")
        assembly = value.get("assembly")
        if assembly is not None and not (isinstance(assembly, str) and assembly.strip()):
            raise SpecError(f"{where}: `assembly` must be a non-empty string")
        namespace, cls = _split_class(value["class"].strip(), where)
        method = value["method"].strip()
        if not _METHOD_RE.match(method):
            raise SpecError(f"{where}: {method!r} is not a method name")
        return MethodSpec(namespace, cls, method, args, assembly.strip() if assembly else None)
    if not isinstance(value, str) or not value.strip():
        raise SpecError(f"{where}: expected \"Namespace.Class::Method\" or an object, got {value!r}")
    text = value.strip()
    class_part, sep, rest = text.partition("::")
    if not sep or not class_part or not rest:
        raise SpecError(f"{where}: {text!r} is not Namespace.Class::Method[/N]")
    method, slash, count = rest.rpartition("/")
    if not slash:
        method, count = rest, None
    elif not count.isdigit():
        raise SpecError(f"{where}: {text!r}: the part after `/` is a parameter count, got {count!r}")
    if not _METHOD_RE.match(method):
        raise SpecError(f"{where}: {text!r}: {method!r} is not a method name")
    namespace, cls = _split_class(class_part, where)
    return MethodSpec(namespace, cls, method, None if count is None else int(count))


# --------------------------------------------------------------------------------------
# metadata dumps
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class MethodEntry:
    cls: str                      # `Ns.Class` / `Ns.Outer.Inner`, as the dump spells it
    method: str
    rva: int
    argc: Optional[int] = None    # None: the dump did not say

    def __str__(self):
        return f"{self.cls}::{self.method}" + ("" if self.argc is None else f"/{self.argc}")


def _split_params(text):
    """The comma-separated parameters of a signature, ignoring commas inside <> () []."""
    parts, depth, cur = [], 0, []
    for ch in text:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail or parts:
        parts.append(tail)
    return [p for p in parts if p]


def count_c_params(signature):
    """Declared parameters of an Il2CppDumper `Signature` - `void Ns_C__M (Ns_C_o* __this, int a,
    const MethodInfo* method);` - without the implicit `__this` and trailing MethodInfo. None if
    the text does not look like a signature."""
    if not isinstance(signature, str) or "(" not in signature or ")" not in signature:
        return None
    inner = signature[signature.index("(") + 1:signature.rindex(")")]
    params = _split_params(inner)
    if params and "MethodInfo" in params[-1]:
        params = params[:-1]
    if params and params[0].rstrip().endswith("__this"):
        params = params[1:]
    return len(params)


def count_cs_params(parameters):
    """Parameter count of the text between the parentheses of a C# declaration."""
    return len(_split_params(parameters))


class MethodIndex:
    """Every method a metadata dump names, with where the dump says it was compiled."""

    def __init__(self, entries, source="", fmt=""):
        self.entries = list(entries)
        self.source = str(source)
        self.format = fmt
        by_name = {}
        for e in self.entries:
            by_name.setdefault((e.cls, e.method), []).append(e)
        self._by_name = by_name

    def __len__(self):
        return len(self.entries)

    def lookup(self, spec):
        """The ONE entry `spec` names. Raises NameLookupError: not_found, or ambiguous (more
        than one address - overloads `spec` does not tell apart, or one name at two addresses)."""
        spec = parse_method_spec(spec)
        found = self._by_name.get((spec.qualified_class, spec.method), [])
        exact = [e for e in found if spec.argc is None or e.argc is None or e.argc == spec.argc]
        distinct = {}
        for e in exact:
            distinct.setdefault(e.rva, e)
        matches = list(distinct.values())
        if not matches:
            if found and spec.argc is not None:
                have = sorted({e.argc for e in found if e.argc is not None})
                raise NameLookupError(
                    f"{spec}: the dump has {spec.qualified_class}::{spec.method}, but with "
                    f"{', '.join(map(str, have)) or 'an unknown number of'} parameter(s), not {spec.argc}",
                    "not_found", found)
            raise NameLookupError(f"{spec}: not in the metadata dump ({len(self)} methods read)",
                                  "not_found")
        if len(matches) > 1:
            where = ", ".join(f"0x{m.rva:x}" + ("" if m.argc is None else f" ({m.argc} param)")
                              for m in sorted(matches, key=lambda m: m.rva))
            hint = ("; add /N for the parameter count" if spec.argc is None
                    and len({m.argc for m in matches}) > 1 else "")
            raise NameLookupError(f"{spec}: {len(matches)} different methods answer to it ({where}){hint}",
                                  "ambiguous", matches)
        return matches[0]


_HEX = re.compile(r"0[xX][0-9A-Fa-f]+")


def _entries_from_script_json(data, path):
    methods = data.get("ScriptMethod") if isinstance(data, dict) else None
    if not isinstance(methods, list):
        raise MetadataError(f"{path}: a JSON file, but no `ScriptMethod` list - this reads Il2CppDumper's "
                            f"script.json (or use dump.cs / a `NAME ADDRESS` symbol map)")
    out = []
    for m in methods:
        if not isinstance(m, dict):
            continue
        name, address = m.get("Name"), m.get("Address")
        if not isinstance(name, str) or "$$" not in name:
            continue
        if isinstance(address, bool) or not isinstance(address, int) or address <= 0:
            continue
        cls, _, method = name.rpartition("$$")
        out.append(MethodEntry(cls, method, address, count_c_params(m.get("Signature"))))
    return out


_NAMESPACE_RE = re.compile(r"^\s*//\s*Namespace:\s*(.*?)\s*$")
_RVA_RE = re.compile(r"^\s*//\s*RVA:\s*(0[xX][0-9A-Fa-f]+)\b")
_TYPE_RE = re.compile(r"\b(?:class|struct|interface)\s+([^\s:{<]+)(?:<[^>]*>)?[^\n]*//\s*TypeDefIndex:")
_DECL_RE = re.compile(r"([^\s(]+)\s*\((.*)\)")


def _entries_from_dump_cs(text):
    out, namespace, cls, pending = [], "", None, None
    for line in text.splitlines():
        ns = _NAMESPACE_RE.match(line)
        if ns:
            namespace, cls, pending = ns.group(1), None, None
            continue
        ty = _TYPE_RE.search(line)
        if ty:
            cls = f"{namespace}.{ty.group(1)}" if namespace else ty.group(1)
            pending = None
            continue
        rva = _RVA_RE.match(line)
        if rva:
            pending = int(rva.group(1), 16)
            continue
        if pending is not None and line.strip() and not line.lstrip().startswith("//"):
            if cls is not None and pending > 0:
                # `public void Unpack(IntPtr buf) { }` - the name is the token before the first `(`
                head = line.split("{", 1)[0] if "(" not in line else line
                decl = _DECL_RE.search(head)
                if decl:
                    out.append(MethodEntry(cls, decl.group(1), pending, count_cs_params(decl.group(2))))
            pending = None
    return out


def _entries_from_symbol_map(text, path):
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        tokens = line.replace("\t", " ").split()
        hexes = [t for t in tokens if _HEX.fullmatch(t)]
        names = [t for t in tokens if not _HEX.fullmatch(t)]
        if len(hexes) != 1 or len(names) != 1:
            raise MetadataError(f"{path}:{n}: expected `NAME ADDRESS` (one name, one 0x... address), "
                                f"got {raw.strip()!r}")
        name, rva = names[0], int(hexes[0], 16)
        if "$$" in name:
            cls, _, method = name.rpartition("$$")
        elif "::" in name:
            cls, _, method = name.rpartition("::")
        else:
            raise MetadataError(f"{path}:{n}: {name!r} is neither Ns.Class$$Method nor Ns.Class::Method")
        if rva > 0 and cls and method:
            out.append(MethodEntry(cls.replace("/", "."), method, rva))
    return out


def sniff_format(head):
    """\"script.json\", \"dump.cs\" or \"symbols\", from the first bytes of a metadata file."""
    stripped = head.lstrip()
    if stripped.startswith("{"):
        return "script.json"
    if "// Namespace:" in head or "// RVA:" in head or "// TypeDefIndex:" in head:
        return "dump.cs"
    return "symbols"


def load_metadata(path):
    """A `MethodIndex` from the metadata file at `path` (the format is recognised from its
    content, not its extension). Raises MetadataError when it cannot be read or holds no method."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        raise MetadataError(f"{path}: {e}") from e
    fmt = sniff_format(text[:65536])
    if fmt == "script.json":
        try:
            entries = _entries_from_script_json(json.loads(text), path)
        except json.JSONDecodeError as e:
            raise MetadataError(f"{path}: not valid JSON: {e}") from e
    elif fmt == "dump.cs":
        entries = _entries_from_dump_cs(text)
    else:
        entries = _entries_from_symbol_map(text, path)
    if not entries:
        raise MetadataError(f"{path}: read as {fmt}, but it names no method with an address")
    return MethodIndex(entries, path, fmt)
