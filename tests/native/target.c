/* The "app" the real-Frida tests spawn (tests/test_frida_real.py).
 *
 * retk/_common.py's spawn_agent() starts its target with no arguments, so what
 * to do comes from a file named "target.cfg" next to this executable:
 *
 *   line 1   path of the process image to map (the test's fake record table)
 *   line 2   hex address to map it at - above 4 GiB, so a record's pointers need
 *            more than 32 bits, like a real process's
 *   line 3   path of the library to dlopen (ignored in the linked build)
 *   rest     "OFFSET_HEX:MODE": call unpack_a(image + OFFSET, MODE)
 *
 * Two more line kinds serve the snapshot tests (tests/test_snapshot_real.py): "klass:OFFSET_HEX" stores the
 * fake IL2CPP's class pointer for ExampleTableA at the start of the record at OFFSET (so the heap holds
 * real instances of that class), and "publish:OFFSET_HEX" queues a record, "publish!" then hands the queue to
 * fake_il2cpp_publish(), which fills the static fields of ExampleNamespace.ExampleTableB.
 *
 * If the library has an IL2CPP of its own (fake_il2cpp.c: il2cpp_init, or renamed_il2cpp_init in
 * the renamed variant), il2cpp_init() is called first - after the hook is in place, like a real
 * game would - and a line "wait:MS" sleeps MS milliseconds (so a test can attach AFTER init).
 *
 * Linked build: libtarget.so is loaded with the program, before the agent
 * could look for it. -DUSE_DLOPEN build: it is dlopen()ed a moment after the
 * start, so the agent has to wait for it (waitForModule's module observer).
 * Either way the program pauses first so the hook is in place before the first
 * call, then keeps itself alive until the test kills it.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef unsigned long long (*unpack_fn)(void *, int);
typedef int (*init_fn)(const char *);
typedef void *(*class_fn)(void);
typedef void (*publish_fn)(void **, int);
#ifndef USE_DLOPEN
extern unsigned long long unpack_a(void *, int);
extern int il2cpp_init(const char *) __attribute__((weak));   /* absent in the plain libtarget.so */
extern void *fake_il2cpp_table_a_class(void) __attribute__((weak));
extern void fake_il2cpp_publish(void **, int) __attribute__((weak));
#endif

int main(void)
{
    char exe[4096], cfgpath[4200], blob[4096], lib[4096], line[128];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n < 0) return 2;
    exe[n] = 0;
    char *slash = strrchr(exe, '/');
    if (!slash) return 2;
    *slash = 0;
    snprintf(cfgpath, sizeof cfgpath, "%s/target.cfg", exe);

    FILE *cfg = fopen(cfgpath, "r");
    if (!cfg) return 2;
    unsigned long long base;
    if (fscanf(cfg, "%4095s %llx %4095s", blob, &base, lib) != 3) return 2;

    FILE *f = fopen(blob, "rb");
    if (!f) return 5;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    void *want = (void *)base;
    char *mem = mmap(want, (size_t)size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (mem != want) return 3;
    if (fread(mem, 1, (size_t)size, f) != (size_t)size) return 6;
    fclose(f);

    usleep(300000);                       /* let the agent's hook go in before the first call */
#ifdef USE_DLOPEN
    void *h = dlopen(lib, RTLD_NOW);
    if (!h) return 4;
    unpack_fn fn = (unpack_fn)dlsym(h, "unpack_a");
    if (!fn) return 4;
    init_fn init = (init_fn)dlsym(h, "il2cpp_init");
    if (!init) init = (init_fn)dlsym(h, "renamed_il2cpp_init");
    class_fn table_a_class = (class_fn)dlsym(h, "fake_il2cpp_table_a_class");
    publish_fn publish = (publish_fn)dlsym(h, "fake_il2cpp_publish");
    usleep(300000);
#else
    unpack_fn fn = unpack_a;
    init_fn init = il2cpp_init;
    class_fn table_a_class = fake_il2cpp_table_a_class;
    publish_fn publish = fake_il2cpp_publish;
#endif
    void *queued[64];
    int nqueued = 0;
    if (init) init("fake");
    while (fscanf(cfg, "%127s", line) == 1) {
        unsigned long off = 0;
        int mode = 0;
        int ms = 0;
        if (sscanf(line, "wait:%d", &ms) == 1) { usleep((useconds_t)ms * 1000); continue; }
        if (sscanf(line, "klass:%lx", &off) == 1) { if (table_a_class) *(void **)(mem + off) = table_a_class(); continue; }
        if (sscanf(line, "publish:%lx", &off) == 1) { if (nqueued < 64) queued[nqueued++] = mem + off; continue; }
        if (!strcmp(line, "publish!")) { if (publish) publish(queued, nqueued); continue; }
        if (sscanf(line, "%lx:%d", &off, &mode) != 2) return 7;
        fn(mem + off, mode);
    }
    sleep(30);                            /* the test kills us once it has what it needs */
    return 0;
}
