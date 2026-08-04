// test_code.cpp -- the PE and static-analysis concepts, as compilable code.
//
// Everything here is benign and self-contained. Nothing downloads, nothing
// injects, nothing touches another process. The point is to make each concept
// visible in a binary you built yourself, so you can point SMA at it.
//
// Build (Developer Command Prompt):
//     cl /LD test_code.cpp        -> test_code.dll
//     cl     test_code.cpp        -> test_code.exe
//
// Then:
//     sma scan      test_code.exe
//     sma functions test_code.exe
//     sma disasm    test_code.exe --addr <rva> --count 40

#include <windows.h>
#include <stdio.h>
#include <string.h>

// ===========================================================================
// PART A -- SECTION FLAGS, AND MAKING A SECTION EXECUTABLE
// ===========================================================================
//
// A section's permissions are just bits in the section header:
//     IMAGE_SCN_MEM_READ    0x40000000
//     IMAGE_SCN_MEM_WRITE   0x80000000
//     IMAGE_SCN_MEM_EXECUTE 0x20000000
//
// You never "call" IMAGE_SCN_MEM_EXECUTE -- it is a flag you ask the LINKER to
// set. ".text" is a naming convention, nothing more. Any section can be +X.
//
// This creates a section named .mycode and marks it Execute+Read+Write.
// The letters in /SECTION:name,ERW map onto those three flags.
#pragma section(".mycode", execute, read, write)
#pragma comment(linker, "/SECTION:.mycode,ERW")

// Put actual bytes in it. x86-64 machine code for:  mov eax, 42 ; ret
__declspec(allocate(".mycode"))
unsigned char g_codeInSection[] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };

// SMA on this binary will show:
//     .mycode   ...  RWX   <- W+X
// and `sma functions` WILL sweep it, because it filters on the X flag rather
// than on the name ".text". Hiding code in a section called .rsrc or .data
// does not evade it -- as long as the flag is set.
void RunCodeFromCustomSection(void)
{
    int (*fn)(void) = (int (*)(void))g_codeInSection;
    printf("code in .mycode returned %d\n", fn());
}

// ===========================================================================
// PART B -- FLIPPING PERMISSIONS AT RUNTIME WITH VirtualProtect
// ===========================================================================
//
// This is the part that confused you, so, precisely:
//
// Protection is a property of a PAGE (4 KB) of memory, not of a file section.
// Once the loader has mapped the image, you can change any page's protection
// with VirtualProtect -- INCLUDING pages belonging to your own .data section.
//
// The usual sequence, and the one your payload performs:
//     1. VirtualAlloc(..., PAGE_READWRITE)   -- get writable memory
//     2. memcpy instructions into it          -- write, cannot execute yet
//     3. VirtualProtect(..., PAGE_EXECUTE_READ) -- now executable, not writable
//     4. call it
//
// Step 3 does not "swap the W flag for the X flag" as a bit operation -- you
// pass a whole new protection constant that replaces the old one. Going
// straight to PAGE_EXECUTE_READWRITE (W and X at once) works too and is what
// most packers do, which is why W+X is worth flagging.
//
// Why bother with the RW -> RX dance at all? Because DEP (Data Execution
// Prevention -- the CPU's NX/No-eXecute bit) faults the instant you fetch an
// instruction from a page that is not marked executable.
void FlipPermissionsAtRuntime(void)
{
    SIZE_T size = 4096;

    // 1. Writable, NOT executable.
    unsigned char *mem = (unsigned char *)VirtualAlloc(
        NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return;

    // 2. Write instructions:  mov eax, 7 ; ret
    unsigned char code[] = { 0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3 };
    memcpy(mem, code, sizeof(code));

    // Calling it HERE would fault -- the page is not executable yet.

    // 3. Replace the protection wholesale. `old` receives the previous value.
    DWORD old = 0;
    if (VirtualProtect(mem, size, PAGE_EXECUTE_READ, &old)) {
        int (*fn)(void) = (int (*)(void))mem;
        printf("runtime-allocated code returned %d\n", fn());  // 4. call it
    }

    VirtualFree(mem, 0, MEM_RELEASE);
}

// You can do the same to your OWN image. This makes a page of .data executable
// -- a section SMA reports as RW-, with no X flag on disk.
//
// THIS IS THE REAL GAP in `sma functions`: it sweeps sections whose X flag is
// set in the file. Code that only becomes executable after this call lives in
// a section SMA never sweeps. Static analysis can still see the VirtualProtect
// call and the buffer it points at -- but nothing in the headers says "there is
// code here."
static unsigned char g_dataBuffer[4096];

void MakeOwnDataSectionExecutable(void)
{
    unsigned char code[] = { 0xB8, 0x63, 0x00, 0x00, 0x00, 0xC3 };  // mov eax,99; ret
    memcpy(g_dataBuffer, code, sizeof(code));

    DWORD old = 0;
    if (VirtualProtect(g_dataBuffer, sizeof(g_dataBuffer), PAGE_EXECUTE_READ, &old)) {
        int (*fn)(void) = (int (*)(void))g_dataBuffer;
        printf(".data page, made executable, returned %d\n", fn());
    }
}

// ===========================================================================
// PART C -- "ENCRYPTED" BYTES: WHAT THAT ACTUALLY MEANS
// ===========================================================================
//
// Your model was: encrypted bytes are meaningless, so the CPU disregards them.
//
// The CPU never disregards anything. Point it at encrypted bytes and it will
// cheerfully decode them as instructions and execute the nonsense that results
// -- usually crashing, occasionally doing something wild. Encryption does not
// make bytes unreadable; it makes them meaningless AS INSTRUCTIONS. That is
// why the packer must decrypt BEFORE jumping.
//
// The simplest real scheme, and still the most common in practice: XOR.
//
//     plaintext ^ key = ciphertext
//     ciphertext ^ key = plaintext      (same operation both directions)
//
// So "encrypting" a byte is one instruction. Here is 0xB8 with key 0x5A:
//
//     0xB8 ^ 0x5A = 0xE2      <- stored in the file
//     0xE2 ^ 0x5A = 0xB8      <- recovered at runtime

#define XOR_KEY 0x5A

// mov eax, 123 ; ret   -- each byte XORed with 0x5A.
// B8 7B 00 00 00 C3  ->  E2 21 5A 5A 5A 99
static unsigned char g_encrypted[] = { 0xE2, 0x21, 0x5A, 0x5A, 0x5A, 0x99 };

// This is a packer's unpacking stub, in miniature.
//
// NOW THE POINT YOU ALREADY WORKED OUT, AND YOU WERE RIGHT:
// the key has to be here. The CPU needs it, so it must be in the file, and
// anything the CPU can reach, you can reach by reading. XOR_KEY compiles to a
// literal 0x5A sitting in the instruction stream. Look at the disassembly of
// this function and you will see both the key AND the algorithm.
//
//     sma functions test_code.exe          <- find this function's RVA
//     sma disasm test_code.exe --addr <rva> --count 40
//
// That is why static analysis of packers so often succeeds: the decryptor is
// a complete, readable description of how to recover the payload.
void UnpackAndRun(void)
{
    SIZE_T size = 4096;
    unsigned char *mem = (unsigned char *)VirtualAlloc(
        NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return;

    // The decryption loop. Trivially readable in ASM.
    for (size_t i = 0; i < sizeof(g_encrypted); i++) {
        mem[i] = g_encrypted[i] ^ XOR_KEY;
    }

    DWORD old = 0;
    if (VirtualProtect(mem, size, PAGE_EXECUTE_READ, &old)) {
        int (*fn)(void) = (int (*)(void))mem;
        printf("decrypted code returned %d\n", fn());   // 123
    }
    VirtualFree(mem, 0, MEM_RELEASE);
}

// THE EXCEPTION -- when the key is NOT in the file.
//
// "Environmental keying": derive the key from something only present on the
// target machine. Now the key genuinely is not shippable, and static analysis
// cannot recover the payload no matter how carefully you read -- because the
// information is not there to recover. You would need the victim's environment.
//
// You can still read this function and learn exactly WHAT it keys on, which
// tells you what the target was. That is often the more useful finding.
void EnvironmentallyKeyedUnpack(void)
{
    wchar_t name[256] = { 0 };
    DWORD len = 256;
    if (!GetComputerNameW(name, &len)) return;

    unsigned char key = 0;
    for (DWORD i = 0; i < len; i++) {
        key = (unsigned char)(key * 31 + (unsigned char)name[i]);
    }

    // Correct only on the machine whose name produces this key. On any other
    // host it decrypts to garbage -- and on YOUR analysis machine, you cannot
    // brute-force it without knowing what plaintext to look for.
    printf("derived key: 0x%02X (machine-dependent)\n", key);
}

// ===========================================================================
// PART D -- THE FOUR LIMITS, ONE FUNCTION EACH
// ===========================================================================

// --- 1. PATH EXPLOSION ------------------------------------------------------
// Every branch doubles the number of possible routes. Ten branches is 2^10 =
// 1,024 paths through ONE function. Your payload has ~1,026 functions.
// You cannot enumerate them; there are more paths than atoms in short order.
//
// Every instruction here is readable. Enumerating the behaviour is not.
int PathExplosion(int a, int b, int c, int d, int e)
{
    int r = 0;
    if (a > 0) r += 1;  else r -= 1;
    if (b > 0) r += 2;  else r -= 2;
    if (c > 0) r += 4;  else r -= 4;
    if (d > 0) r += 8;  else r -= 8;
    if (e > 0) r += 16; else r -= 16;
    if (r > 10) r *= 2;
    if (r < -10) r /= 2;
    if (r % 3 == 0) r += 100;
    if (r % 5 == 0) r += 200;
    if (r % 7 == 0) r += 300;
    return r;   // 2^10 = 1024 possible routes to this line
}

// --- 2. DATA DEPENDENCE -----------------------------------------------------
// The single most common reason static analysis stops. Both branches are fully
// visible. Which one runs depends on a value that does not exist until the
// program runs. Nothing is hidden -- the information simply is not present yet.
void DataDependence(void)
{
    DWORD ticks = GetTickCount();      // unknowable statically
    if (ticks % 2 == 0) {
        printf("even branch\n");
    } else {
        printf("odd branch\n");
    }
}

// --- 3. SELF-MODIFYING CODE -------------------------------------------------
// The bytes you read on disk are NOT the bytes that execute. Disassembling the
// file shows you the recipe, not the meal.
//
// Below, `target` returns 1 on disk. Before it is ever called, we overwrite the
// immediate operand so it returns 2. Static disassembly says 1. It returns 2.
static unsigned char g_patchable[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };

void SelfModifyingCode(void)
{
    DWORD old = 0;
    if (!VirtualProtect(g_patchable, sizeof(g_patchable), PAGE_EXECUTE_READWRITE, &old))
        return;

    g_patchable[1] = 0x02;      // rewrite the operand: "mov eax,1" -> "mov eax,2"

    int (*fn)(void) = (int (*)(void))g_patchable;
    printf("static read says 1, actual result is %d\n", fn());
}

// --- 4. VOLUME --------------------------------------------------------------
// Not a theoretical limit -- a human one. Your payload has ~1,026 functions and
// ~3,200 call sites. At one minute per function that is seventeen hours, and
// most of those functions are CRT boilerplate you do not care about.
//
// This is precisely the problem `sma functions` exists to solve: it will not
// tell you what matters, but it narrows 1,026 addresses down to the handful
// that touch VirtualAlloc, VirtualProtect, or the network.
void Volume(void) { /* imagine this 1,026 times */ }

// ===========================================================================
// PART E -- ENTRY POINT
// ===========================================================================
//
// "The entry point is in the header" means literally this: the PE optional
// header has a field, AddressOfEntryPoint, at offset +16. It holds one RVA.
// SMA reads it in pe.rs and prints it as "entry point : 0x19c0 (RVA)".
//
// It is guaranteed present and guaranteed readable, because the loader needs it
// to know where to start. That is your thread-end: there is ALWAYS a first
// instruction you can find and read.
//
// Note that `main` is not it. The real entry point is the CRT startup stub,
// which initialises the runtime and then calls main. That is why `sma functions`
// labels an address [entry] that is not the function you wrote.

int main(int argc, char **argv)
{
    (void)argv;
    RunCodeFromCustomSection();
    FlipPermissionsAtRuntime();
    MakeOwnDataSectionExecutable();
    UnpackAndRun();
    EnvironmentallyKeyedUnpack();
    SelfModifyingCode();
    DataDependence();
    printf("PathExplosion -> %d\n", PathExplosion(argc, 1, -1, 1, -1));
    return 0;
}
