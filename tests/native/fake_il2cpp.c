/* A tiny IL2CPP stand-in for the real-Frida tests (tests/test_frida_real.py, test_names_real.py).
 *
 * It exports the slice of the IL2CPP C API that scripts/_resolve.js calls, over a made-up
 * metadata model, with the REAL signatures and the real MethodInfo convention (the first member
 * is the method pointer). The methods point at real functions of this library, so a lookup by
 * name must end at the address Frida can hook:
 *
 *   ExampleNamespace.ExampleTableA   Unpack/1 -> unpack_a   Unpack/2 -> unpack_a2   Reset/0 -> reset_fn
 *                                    fields id 0x10, weight 0x14, enabled 0x18, label 0x20
 *   ExampleNamespace.Outer/Inner     Run/0 -> inner_run
 *   ExampleNamespace.Twin            exists in BOTH assemblies (an ambiguous class)
 *   ExampleNamespace.Abstract        a method with no code pointer
 *   ExampleNamespace.ExampleTableB   STATIC fields holding a table, once fake_il2cpp_publish() has been
 *                                    called (target.c does, for the snapshot tests): `all` a List<T>
 *                                    (capacity larger than _size), `rows` an array (with a null slot),
 *                                    `one` a single record, `empty` null
 *
 * The runtime is "down" until il2cpp_init() has been called: il2cpp_domain_get() is NULL before,
 * like the real one. Compile with -DPFX=renamed_ to export every function under a different name
 * (a build that renames its IL2CPP exports: the profile's `names.exports` maps them back).
 *
 * Built with `cc -shared -fPIC` together with libtarget.c, so unpack_a is the library's own.
 */
#include <stddef.h>
#include <string.h>

#define CAT_(a, b) a##b
#define CAT(a, b) CAT_(a, b)
#ifndef PFX
#define PFX
#endif
#define API(name) CAT(PFX, name)

extern unsigned long long unpack_a(void *, int);
unsigned long long unpack_a2(void *r, int m) { (void)r; (void)m; return 0; }
unsigned long long reset_fn(void) { return 0; }
unsigned long long inner_run(void) { return 0; }

typedef struct { const char *name; int offset; void **slot; } FieldInfo;      /* slot: a static field's storage */
typedef struct { void *methodPointer; const char *name; int argc; } MethodInfo;   /* methodPointer FIRST */
typedef struct Class {
    const char *ns, *name;
    MethodInfo *methods; int nmethods;
    FieldInfo *fields; int nfields;
    struct Class **nested; int nnested;
} Class;
typedef struct { const char *name; Class **classes; int n; } Image;
typedef struct { Image *image; } Assembly;

static MethodInfo table_a_methods[] = {
    { (void *)unpack_a, "Unpack", 1 }, { (void *)unpack_a2, "Unpack", 2 }, { (void *)reset_fn, "Reset", 0 },
};
static FieldInfo table_a_fields[] = {
    { "id", 0x10 }, { "weight", 0x14 }, { "enabled", 0x18 }, { "label", 0x20 },
};
static Class table_a = { "ExampleNamespace", "ExampleTableA", table_a_methods, 3, table_a_fields, 4, NULL, 0 };

static MethodInfo inner_methods[] = { { (void *)inner_run, "Run", 0 } };
static Class inner = { "ExampleNamespace", "Inner", inner_methods, 1, NULL, 0, NULL, 0 };
static Class *outer_nested[] = { &inner };
static Class outer = { "ExampleNamespace", "Outer", NULL, 0, NULL, 0, outer_nested, 1 };

static MethodInfo abstract_methods[] = { { NULL, "Abstract", 0 } };
static Class abstract_class = { "ExampleNamespace", "Abstract", abstract_methods, 1, NULL, 0, NULL, 0 };

static MethodInfo twin_methods[] = { { (void *)reset_fn, "Go", 0 } };
static Class twin_1 = { "ExampleNamespace", "Twin", twin_methods, 1, NULL, 0, NULL, 0 };
static Class twin_2 = { "ExampleNamespace", "Twin", twin_methods, 1, NULL, 0, NULL, 0 };

/* System.Collections.Generic.List<T>'s instance fields, as the runtime lays them out (after the 0x10 header) */
static FieldInfo list_fields[] = { { "_items", 0x10, NULL }, { "_size", 0x18, NULL } };
static Class list_class = { "System.Collections.Generic", "List`1", NULL, 0, list_fields, 2, NULL, 0 };
static Class array_class = { "System", "Object[]", NULL, 0, NULL, 0, NULL, 0 };

static void *static_all, *static_rows, *static_one, *static_empty;
static FieldInfo table_b_fields[] = {
    { "all", 0, &static_all }, { "rows", 0, &static_rows }, { "one", 0, &static_one }, { "empty", 0, &static_empty },
};
static Class table_b = { "ExampleNamespace", "ExampleTableB", NULL, 0, table_b_fields, 4, NULL, 0 };

static Class *csharp_classes[] = { &table_a, &outer, &abstract_class, &twin_1, &table_b };
static Class *other_classes[] = { &twin_2 };
static Image csharp = { "Assembly-CSharp.dll", csharp_classes, 5 };
static Image other = { "Other.dll", other_classes, 1 };
static Assembly assemblies[] = { { &other }, { &csharp } };
static Assembly *assembly_ptrs[] = { &assemblies[0], &assemblies[1] };

static int g_up;
static int g_domain;

int API(il2cpp_init)(const char *name) { (void)name; g_up = 1; return 1; }
int API(il2cpp_init_utf16)(const void *name) { (void)name; g_up = 1; return 1; }
void *API(il2cpp_domain_get)(void) { return g_up ? &g_domain : NULL; }
void *API(il2cpp_thread_attach)(void *domain) { return domain; }
void **API(il2cpp_domain_get_assemblies)(void *domain, size_t *size)
{
    (void)domain;
    *size = 2;
    return (void **)assembly_ptrs;
}
void *API(il2cpp_assembly_get_image)(void *assembly) { return ((Assembly *)assembly)->image; }
const char *API(il2cpp_image_get_name)(void *image) { return ((Image *)image)->name; }

void *API(il2cpp_class_from_name)(void *image, const char *ns, const char *name)
{
    Image *im = image;
    for (int i = 0; i < im->n; i++)
        if (!strcmp(im->classes[i]->ns, ns) && !strcmp(im->classes[i]->name, name)) return im->classes[i];
    return NULL;
}
const char *API(il2cpp_class_get_name)(void *klass) { return ((Class *)klass)->name; }
void *API(il2cpp_class_get_nested_types)(void *klass, void **iter)
{
    Class *c = klass;
    size_t i = (size_t)*iter;
    if (i >= (size_t)c->nnested) return NULL;
    *iter = (void *)(i + 1);
    return c->nested[i];
}
void *API(il2cpp_class_get_methods)(void *klass, void **iter)
{
    Class *c = klass;
    size_t i = (size_t)*iter;
    if (i >= (size_t)c->nmethods) return NULL;
    *iter = (void *)(i + 1);
    return &c->methods[i];
}
void *API(il2cpp_class_get_method_from_name)(void *klass, const char *name, int argc)
{
    Class *c = klass;
    for (int i = 0; i < c->nmethods; i++)
        if (!strcmp(c->methods[i].name, name) && (argc < 0 || c->methods[i].argc == argc)) return &c->methods[i];
    return NULL;
}
const char *API(il2cpp_method_get_name)(void *method) { return ((MethodInfo *)method)->name; }
unsigned int API(il2cpp_method_get_param_count)(void *method) { return (unsigned int)((MethodInfo *)method)->argc; }
void *API(il2cpp_class_get_field_from_name)(void *klass, const char *name)
{
    Class *c = klass;
    for (int i = 0; i < c->nfields; i++)
        if (!strcmp(c->fields[i].name, name)) return &c->fields[i];
    return NULL;
}
size_t API(il2cpp_field_get_offset)(void *field) { return (size_t)((FieldInfo *)field)->offset; }

void API(il2cpp_field_static_get_value)(void *field, void *out)
{
    FieldInfo *f = field;
    *(void **)out = f->slot ? *f->slot : NULL;
}

/* ---- test helpers, not part of the IL2CPP API ---------------------------------------------------- */

void *fake_il2cpp_table_a_class(void) { return &table_a; }

typedef struct { void *klass, *monitor, *items; int size; } ListObj;                 /* List<T>: _items at 0x10, _size at 0x18 */
typedef struct { void *klass, *monitor, *bounds; unsigned long long max_length; void *items[66]; } ArrObj;
static ListObj list_obj;
static ArrObj list_backing, rows_obj;

/* Build the static fields' contents from `n` record addresses (n <= 64). */
void fake_il2cpp_publish(void **records, int n)
{
    memset(&list_backing, 0, sizeof list_backing);
    memset(&rows_obj, 0, sizeof rows_obj);
    list_backing.klass = &array_class;
    list_backing.max_length = (unsigned long long)n + 2;           /* capacity beyond _size: the tail is stale */
    rows_obj.klass = &array_class;
    rows_obj.max_length = (unsigned long long)n + 1;               /* one null slot at the end */
    for (int i = 0; i < n; i++) {
        list_backing.items[i] = records[i];
        rows_obj.items[i] = records[i];
    }
    list_backing.items[n] = records[0];                            /* stale entry past _size: must not be read */
    list_obj.klass = &list_class;
    list_obj.items = &list_backing;
    list_obj.size = n;
    static_all = &list_obj;
    static_rows = &rows_obj;
    static_one = n ? records[0] : NULL;
    static_empty = NULL;
}
