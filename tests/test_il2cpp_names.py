"""
Tests for retk/il2cpp_names.py: the name grammar, the three metadata formats and the lookup.

Everything uses the template's made-up names (ExampleNamespace.ExampleTableA ...). The rule
these tests pin is that a name which the metadata does not settle is an ERROR, never a pick:
two overloads, one name at two addresses, a name that is not there.

Run from the repo root:

    pytest tests/test_il2cpp_names.py
"""
import json

import pytest

from retk import il2cpp_names as names
CLASS = "ExampleNamespace.ExampleTableA"

DUMP_CS = """// Namespace: ExampleNamespace
public class ExampleTableA : Object // TypeDefIndex: 10
{
	// Fields
	public int id; // 0x10

	// Methods

	// RVA: 0x1A2B30 Offset: 0x1A2B30 VA: 0x1A2B30
	public int Unpack(IntPtr buf) { }

	// RVA: 0x1A2C00 Offset: 0x1A2C00 VA: 0x1A2C00
	public int Unpack(IntPtr buf, int mode) { }

	// RVA: 0x1A2D00 Offset: 0x1A2D00 VA: 0x1A2D00
	public void .ctor() { }

	// RVA: 0x1A2E00 Offset: 0x1A2E00 VA: 0x1A2E00
	public Dictionary<int, string> Table(List<int> a, int b) { }

	public abstract void Abstract();
}

// Namespace: ExampleNamespace
public class ExampleTableB // TypeDefIndex: 11
{
	// RVA: 0x1A3000 Offset: 0x1A3000 VA: 0x1A3000
	public int Unpack(IntPtr buf) { }
}
"""


def script_json(*methods):
    return json.dumps({"ScriptMethod": [
        {"Address": a, "Name": n, "Signature": s, "TypeSignature": "iii"} for a, n, s in methods]})


SIG_1 = "int32_t ExampleNamespace_ExampleTableA__Unpack (ExampleNamespace_ExampleTableA_o* __this, System_IntPtr_o buf, const MethodInfo* method);"
SIG_2 = "int32_t ExampleNamespace_ExampleTableA__Unpack (ExampleNamespace_ExampleTableA_o* __this, System_IntPtr_o buf, int32_t mode, const MethodInfo* method);"
SIG_STATIC = "void ExampleNamespace_ExampleTableA__Reset (const MethodInfo* method);"


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# the grammar
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text, namespace, cls, method, argc", [
    (f"{CLASS}::Unpack", "ExampleNamespace", "ExampleTableA", "Unpack", None),
    (f"{CLASS}::Unpack/1", "ExampleNamespace", "ExampleTableA", "Unpack", 1),
    (f"{CLASS}::Unpack/0", "ExampleNamespace", "ExampleTableA", "Unpack", 0),
    ("Global::Run", "", "Global", "Run", None),
    ("A.B.C.D::M", "A.B.C", "D", "M", None),
    ("ExampleNamespace.Outer/Inner::Run", "ExampleNamespace", "Outer/Inner", "Run", None),
    (f"{CLASS}::.ctor", "ExampleNamespace", "ExampleTableA", ".ctor", None),
    (f"{CLASS}::<Start>b__0_0/1", "ExampleNamespace", "ExampleTableA", "<Start>b__0_0", 1),
    ("  ExampleNamespace.ExampleTableA::Unpack  ", "ExampleNamespace", "ExampleTableA", "Unpack", None),
])
def test_a_spec_is_split_into_namespace_class_method_and_argc(text, namespace, cls, method, argc):
    spec = names.parse_method_spec(text)
    assert (spec.namespace, spec.cls, spec.method, spec.argc) == (namespace, cls, method, argc)


def test_a_spec_prints_back_as_it_was_written_and_qualifies_a_nested_class_with_dots():
    assert str(names.parse_method_spec(f"{CLASS}::Unpack/1")) == f"{CLASS}::Unpack/1"
    nested = names.parse_method_spec("ExampleNamespace.Outer/Inner::Run")
    assert str(nested) == "ExampleNamespace.Outer/Inner::Run"
    assert nested.qualified_class == "ExampleNamespace.Outer.Inner"
    assert names.parse_method_spec("Global::Run").qualified_class == "Global"


def test_the_object_form_is_the_only_way_to_name_the_assembly():
    spec = names.parse_method_spec({"class": CLASS, "method": "Unpack", "args": 1, "assembly": "Assembly-CSharp"})
    assert spec == names.MethodSpec("ExampleNamespace", "ExampleTableA", "Unpack", 1, "Assembly-CSharp")
    assert spec.as_agent() == {"namespace": "ExampleNamespace", "class": "ExampleTableA", "method": "Unpack",
                               "args": 1, "assembly": "Assembly-CSharp"}
    # "any overload" travels as -1, and no assembly key at all when none was named
    assert names.parse_method_spec(f"{CLASS}::Unpack").as_agent() == {
        "namespace": "ExampleNamespace", "class": "ExampleTableA", "method": "Unpack", "args": -1}


@pytest.mark.parametrize("bad", [
    "", "   ", "Unpack", "Ns.Class::", "::Method", "Ns.Class::Method/x", "Ns.Class::Method/-1",
    "Ns.Class::two words", "1Ns.Class::Method", "Ns..Class::Method", "Ns.Class/::Method",
    3, None, ["Ns.Class::Method"], True,
])
def test_a_malformed_spec_is_refused_naming_where(bad):
    with pytest.raises(names.SpecError) as e:
        names.parse_method_spec(bad, "names.methods.table_a")
    assert "names.methods.table_a" in str(e.value)


@pytest.mark.parametrize("bad", [
    {"class": CLASS},                                            # no method
    {"method": "Unpack"},                                        # no class
    {"class": CLASS, "method": "Unpack", "args": -1},
    {"class": CLASS, "method": "Unpack", "args": "1"},
    {"class": CLASS, "method": "Unpack", "args": True},
    {"class": CLASS, "method": "Unpack", "assembly": ""},
    {"class": CLASS, "method": "Unpack", "extra": 1},            # a typo must not be ignored
])
def test_a_malformed_object_spec_is_refused(bad):
    with pytest.raises(names.SpecError):
        names.parse_method_spec(bad)


# ---------------------------------------------------------------------------
# reading metadata
# ---------------------------------------------------------------------------

def test_dump_cs_gives_each_method_its_rva_and_parameter_count(tmp_path):
    index = names.load_metadata(write(tmp_path, "dump.cs", DUMP_CS))
    assert index.format == "dump.cs"
    got = {(e.cls, e.method, e.argc): e.rva for e in index.entries}
    assert got == {
        (CLASS, "Unpack", 1): 0x1A2B30,
        (CLASS, "Unpack", 2): 0x1A2C00,
        (CLASS, ".ctor", 0): 0x1A2D00,
        (CLASS, "Table", 2): 0x1A2E00,          # a comma inside <> does not split a parameter
        ("ExampleNamespace.ExampleTableB", "Unpack", 1): 0x1A3000,
    }                                            # the abstract method has no RVA comment: not listed


def test_script_json_reads_the_address_and_counts_parameters_without_this_and_methodinfo(tmp_path):
    path = write(tmp_path, "script.json", script_json(
        (0x1A2B30, f"{CLASS}$$Unpack", SIG_1), (0x1A2C00, f"{CLASS}$$Unpack", SIG_2),
        (0x1A2F00, f"{CLASS}$$Reset", SIG_STATIC), (0x10, "not a method name", "")))
    index = names.load_metadata(path)
    assert index.format == "script.json"
    assert {(e.method, e.argc): e.rva for e in index.entries} == {
        ("Unpack", 1): 0x1A2B30, ("Unpack", 2): 0x1A2C00, ("Reset", 0): 0x1A2F00}


def test_a_symbol_map_takes_either_separator_and_either_column_order(tmp_path):
    path = write(tmp_path, "symbols.txt",
                 f"# a comment\n{CLASS}$$Unpack 0x1a2b30\n0x1a2c00\t{CLASS}::Unpack2   # trailing\n\n")
    index = names.load_metadata(path)
    assert index.format == "symbols"
    assert [(str(e), e.rva) for e in index.entries] == [(f"{CLASS}::Unpack", 0x1A2B30),
                                                        (f"{CLASS}::Unpack2", 0x1A2C00)]


def test_the_format_is_recognised_from_the_content_not_the_extension(tmp_path):
    assert names.load_metadata(write(tmp_path, "whatever.bin", DUMP_CS)).format == "dump.cs"
    assert names.load_metadata(write(tmp_path, "d.txt", script_json((1, f"{CLASS}$$Unpack", SIG_1)))).format == "script.json"


@pytest.mark.parametrize("text, why", [
    ("", "names no method"),
    ("# only comments\n", "names no method"),
    ('{"ScriptString": []}', "ScriptMethod"),
    ("{not json", "not valid JSON"),
    ("just words here\n", "expected `NAME ADDRESS`"),
    ("Ns.Class$$Method 0x10 0x20\n", "expected `NAME ADDRESS`"),
    ("Method 0x10\n", "neither Ns.Class$$Method nor Ns.Class::Method"),
])
def test_unusable_metadata_is_refused_with_the_reason(tmp_path, text, why):
    with pytest.raises(names.MetadataError) as e:
        names.load_metadata(write(tmp_path, "bad", text))
    assert why in str(e.value)


def test_a_missing_metadata_file_is_a_metadata_error(tmp_path):
    with pytest.raises(names.MetadataError):
        names.load_metadata(str(tmp_path / "nope.cs"))


# ---------------------------------------------------------------------------
# the lookup
# ---------------------------------------------------------------------------

@pytest.fixture
def index(tmp_path):
    return names.load_metadata(write(tmp_path, "dump.cs", DUMP_CS))


def test_a_name_that_settles_to_one_method_answers(index):
    assert index.lookup(f"{CLASS}::Unpack/1").rva == 0x1A2B30
    assert index.lookup(f"{CLASS}::Unpack/2").rva == 0x1A2C00
    assert index.lookup(f"{CLASS}::.ctor").rva == 0x1A2D00           # only one overload: no /N needed
    assert index.lookup("ExampleNamespace.ExampleTableB::Unpack").rva == 0x1A3000


def test_two_overloads_without_a_parameter_count_are_ambiguous_and_say_how_to_settle_it(index):
    with pytest.raises(names.NameLookupError) as e:
        index.lookup(f"{CLASS}::Unpack")
    assert e.value.kind == "ambiguous"
    assert {m.rva for m in e.value.matches} == {0x1A2B30, 0x1A2C00}
    assert "add /N" in str(e.value)


def test_a_name_that_is_not_there_is_not_found(index):
    with pytest.raises(names.NameLookupError) as e:
        index.lookup(f"{CLASS}::Nope")
    assert e.value.kind == "not_found" and "not in the metadata dump" in str(e.value)
    with pytest.raises(names.NameLookupError) as e:
        index.lookup("ExampleNamespace.Missing::Unpack")
    assert e.value.kind == "not_found"


def test_the_wrong_parameter_count_says_which_counts_exist(index):
    with pytest.raises(names.NameLookupError) as e:
        index.lookup(f"{CLASS}::Unpack/5")
    assert e.value.kind == "not_found" and "1, 2 parameter(s), not 5" in str(e.value)


def test_one_name_at_two_addresses_is_ambiguous_even_with_the_count(tmp_path):
    path = write(tmp_path, "map.txt", f"{CLASS}$$Unpack 0x1000\n{CLASS}$$Unpack 0x2000\n")
    with pytest.raises(names.NameLookupError) as e:
        names.load_metadata(path).lookup(f"{CLASS}::Unpack")
    assert e.value.kind == "ambiguous" and "2 different methods" in str(e.value)


def test_the_same_method_listed_twice_at_one_address_is_one_method(tmp_path):
    path = write(tmp_path, "map.txt", f"{CLASS}$$Unpack 0x1000\n{CLASS}::Unpack 0x1000\n")
    assert names.load_metadata(path).lookup(f"{CLASS}::Unpack").rva == 0x1000


def test_a_nested_class_is_matched_the_way_the_dumpers_spell_it(tmp_path):
    path = write(tmp_path, "map.txt", "ExampleNamespace.Outer.Inner$$Run 0x1230\n")
    assert names.load_metadata(path).lookup("ExampleNamespace.Outer/Inner::Run").rva == 0x1230


def test_a_dump_that_gives_no_parameter_count_still_answers_a_name_with_one(tmp_path):
    index = names.load_metadata(write(tmp_path, "map.txt", f"{CLASS}$$Unpack 0x1000\n"))
    assert index.lookup(f"{CLASS}::Unpack/3").rva == 0x1000          # the dump cannot contradict it


def test_count_c_params_is_none_for_text_that_is_not_a_signature():
    assert names.count_c_params("") is None and names.count_c_params(None) is None
    assert names.count_c_params("void f (const MethodInfo* method);") == 0
    assert names.count_c_params("void f (A_o* __this, int a, void (*cb)(int, int), const MethodInfo* method);") == 2
