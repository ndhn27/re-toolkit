/* The "game library" the real-Frida tests hook (tests/test_frida_real.py).
 *
 * unpack_a(record, mode) stands in for the app's `...$$unpack` function: the
 * agent hooks it, reads the record out of args[0] when it returns, and judges
 * the return value. `mode` picks what it returns, always as a full 64-bit
 * value, so the tests can see exactly what the agent makes of the upper half
 * of the register:
 *
 *   0  0                    success
 *   1  1                    failure
 *   2  0xdeadbeef00000000   success: the low 32 bits are 0, the high half is garbage
 *   3  0xdeadbeef00000001   failure: low half nonzero, high half garbage
 *   4  0x00000000ffffffff   failure: -1 as an int
 *
 * target_data_marker is DATA, not code: a mapped, writable address inside the module, so the
 * verification agent's refusal to hook non-executable memory can be checked against what the real
 * process reports for it (it is not called by anything).
 *
 * Built with `cc -shared -fPIC`; the tests find the RVAs with `nm -D`.
 */
unsigned long long target_data_marker = 0x7a11da7aULL;

unsigned long long unpack_a(void *record, int mode)
{
    (void)record;
    switch (mode) {
    case 0: return 0ULL;
    case 1: return 1ULL;
    case 2: return 0xdeadbeef00000000ULL;
    case 3: return 0xdeadbeef00000001ULL;
    case 4: return 0x00000000ffffffffULL;
    }
    return 0ULL;
}
