#include "PatchNtoskrnl.hpp"

void PatchReturn0(void* Function)
{
    memcpy(Function, "\x33\xC0\xC3", 3); // xor eax, eax; ret
}

static void DisablePatchGuard(void* ImageBase, uint64_t ImageSize)
{
    // Find the section ranges because some sections are NOACCESS
    auto InitSection = FindSection(ImageBase, "INIT");
    ASSERT(InitSection != nullptr);

    auto InitBase = RVA<uint8_t*>(ImageBase, InitSection->VirtualAddress);
    auto InitSize = InitSection->Misc.VirtualSize;

    auto TextSection = FindSection(ImageBase, ".text");
    ASSERT(TextSection != nullptr);

    auto TextBase = RVA<uint8_t*>(ImageBase, TextSection->VirtualAddress);
    auto TextSize = TextSection->Misc.VirtualSize;

    /*
    nt!KeInitAmd64SpecificState
    INIT:0000000140A4F601 8B C2                  mov     eax, edx
    INIT:0000000140A4F603 99                     cdq
    INIT:0000000140A4F604 41 F7 F8               idiv    r8d
    INIT:0000000140A4F607 89 44 24 30            mov     [rsp+28h+arg_0], eax
    INIT:0000000140A4F60B EB 00                  jmp     short $+2
    */
    auto KeInitAmd64SpecificStateJmp = FIND_PATTERN(InitBase, InitSize, "\x8B\xC2\x99\x41\xF7\xF8");
    ASSERT(KeInitAmd64SpecificStateJmp != nullptr);

    // Prevent the mov from modifying the return address
    memset(RVA<void*>(KeInitAmd64SpecificStateJmp, 6), 0x90, 4); // nop x4

    /*
    nt!KiSwInterrupt
    .text:00000001403FD24E FB                    sti
    .text:00000001403FD24F 48 8D 4D 80           lea     rcx, [rbp+0E8h+var_168]
    .text:00000001403FD253 E8 E8 C2 FD FF        call    KiSwInterruptDispatch
    .text:00000001403FD258 FA                    cli
    */
    auto KiSwInterruptDispatchCall = FIND_PATTERN(TextBase, TextSize, "\xFB\x48\x8D\xCC\xCC\xE8\xCC\xCC\xCC\xCC\xFA");
    ASSERT(KiSwInterruptDispatchCall != nullptr);

    // Prevent KiSwInterruptDispatch from being executed
    memset(KiSwInterruptDispatchCall, 0x90, 11); // nop x11

    /*
    nt!KiVerifyScopesExecute
    INIT:0000000140A16060 48 8B C4                                      mov     rax, rsp
    INIT:0000000140A16063 48 89 58 08                                   mov     [rax+8], rbx
    INIT:0000000140A16067 48 89 70 10                                   mov     [rax+10h], rsi
    INIT:0000000140A1606B 48 89 78 18                                   mov     [rax+18h], rdi
    INIT:0000000140A1606F 4C 89 78 20                                   mov     [rax+20h], r15
    INIT:0000000140A16073 55                                            push    rbp
    INIT:0000000140A16074 48 8B EC                                      mov     rbp, rsp
    INIT:0000000140A16077 48 83 EC 60                                   sub     rsp, 60h
    INIT:0000000140A1607B 83 65 F4 00                                   and     [rbp+var_C], 0
    INIT:0000000140A1607F 0F 57 C0                                      xorps   xmm0, xmm0
    We try to find this:
    INIT:0000000140A16082 48 83 65 E8 00                                and     [rbp+var_18], 0
    INIT:0000000140A16087 48 B8 FF FF FF FF FF FF FF FE                 mov     rax, 0FEFFFFFFFFFFFFFFh
    */
    auto KiVerifyScopesExecuteMid = FIND_PATTERN(InitBase, InitSize, "\x48\x83\xCC\xCC\x00\x48\xB8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE");
    ASSERT(KiVerifyScopesExecuteMid != nullptr);

    auto KiVerifyScopesExecute = FindFunctionStart(ImageBase, KiVerifyScopesExecuteMid);
    ASSERT(KiVerifyScopesExecute != nullptr);

    PatchReturn0(KiVerifyScopesExecute);

    /*
    nt!KiMcaDeferredRecoveryService
    .text:00000001401CCA30 33 C0                                         xor     eax, eax
    .text:00000001401CCA32 8B D8                                         mov     ebx, eax
    .text:00000001401CCA34 8B F8                                         mov     edi, eax
    .text:00000001401CCA36 8B E8                                         mov     ebp, eax
    .text:00000001401CCA38 4C 8B D0                                      mov     r10, rax
    */
    auto KiMcaDeferredRecoveryService = FIND_PATTERN(TextBase, TextSize, "\x33\xC0\x8B\xD8\x8B\xF8\x8B\xE8\x4C\x8B\xD0");
    ASSERT(KiMcaDeferredRecoveryService != nullptr);

    // Find the callers of this function
    int CallerCount = 0;
    for (size_t i = 0, Count = 0; i + 5 < TextSize; i++)
    {
        auto Address = TextBase + i;
        if (*Address == 0xE8) // call disp32
        {
            auto Displacement = *(int32_t*)(Address + 1);
            auto CallDestination = Address + Displacement + 5;
            if (CallDestination == KiMcaDeferredRecoveryService)
            {
                // Skip over the call
                i += 4;

                // There should not be more than two callers
                CallerCount++;

                // Patch out the caller functions at the start
                auto CallerFunction = FindFunctionStart(ImageBase, Address);
                ASSERT(CallerFunction != nullptr);

                PatchReturn0(CallerFunction);
            }
        }
    }
    ASSERT(CallerCount == 2);

    /*
    nt!CcInitializeBcbProfiler
    INIT:0000000140A19354 40 55                                         push    rbp
    INIT:0000000140A19356 53                                            push    rbx
    INIT:0000000140A19357 56                                            push    rsi
    INIT:0000000140A19358 57                                            push    rdi
    INIT:0000000140A19359 41 54                                         push    r12
    INIT:0000000140A1935B 41 55                                         push    r13
    INIT:0000000140A1935D 41 56                                         push    r14
    INIT:0000000140A1935F 41 57                                         push    r15
    INIT:0000000140A19361 48 8D 6C 24 E1                                lea     rbp, [rsp-1Fh]
    INIT:0000000140A19366 48 81 EC B8 00 00 00                          sub     rsp, 0B8h
    INIT:0000000140A1936D 48 B8 D4 02 00 00 80 F7 FF FF                 mov     rax, offset SharedUserData.KdDebuggerEnabled
    */
    auto CcInitializeBcbProfilerMid = FIND_PATTERN(InitBase, InitSize, "\x48\xB8\xD4\x02\x00\x00\x80\xF7\xFF\xFF");
    ASSERT(CcInitializeBcbProfilerMid != nullptr);

    auto CcInitializeBcbProfiler = FindFunctionStart(ImageBase, CcInitializeBcbProfilerMid);
    ASSERT(CcInitializeBcbProfiler != nullptr);

    memcpy(CcInitializeBcbProfiler, "\xB0\x01\xC3", 3); // mov al, 1; ret

    /*
    nt!ExpLicenseWatchInitWorker
    INIT:0000000140A44DF0 48 89 5C 24 08                                mov     [rsp+arg_0], rbx
    INIT:0000000140A44DF5 48 89 6C 24 10                                mov     [rsp+arg_8], rbp
    INIT:0000000140A44DFA 48 89 74 24 18                                mov     [rsp+arg_10], rsi
    INIT:0000000140A44DFF 57                                            push    rdi
    INIT:0000000140A44E00 48 83 EC 30                                   sub     rsp, 30h
    INIT:0000000140A44E04 0F AE E8                                      lfence
    INIT:0000000140A44E07 48 8B 05 B2 8E 2B 00                          mov     rax, cs:KiProcessorBlock
    INIT:0000000140A44E0E 48 8B 70 78                                   mov     rsi, [rax+78h]
    INIT:0000000140A44E12 48 8B 68 70                                   mov     rbp, [rax+70h]
    INIT:0000000140A44E16 48 83 60 78 00                                and     qword ptr [rax+78h], 0
    INIT:0000000140A44E1B 48 83 60 70 00                                and     qword ptr [rax+70h], 0
    INIT:0000000140A44E20 A0 D4 02 00 00 80 F7 FF FF                    mov     al, ds:SharedUserData.KdDebuggerEnabled
    */
    auto ExpLicenseWatchInitWorkerMid = FIND_PATTERN(InitBase, InitSize, "\x48\xB8\xD4\x02\x00\x00\x80\xF7\xFF\xFF");
    ASSERT(ExpLicenseWatchInitWorkerMid != nullptr);

    auto ExpLicenseWatchInitWorker = FindFunctionStart(ImageBase, ExpLicenseWatchInitWorkerMid);
    ASSERT(ExpLicenseWatchInitWorker != nullptr);

    PatchReturn0(ExpLicenseWatchInitWorker);
}

static void DisableDSE(void* ImageBase, uint64_t ImageSize)
{
    auto PageSection = FindSection(ImageBase, "PAGE");
    ASSERT(PageSection != nullptr);

    auto PageBase = RVA<uint8_t*>(ImageBase, PageSection->VirtualAddress);
    auto PageSize = PageSection->Misc.VirtualSize;

    /*
    nt!SepInitializeCodeIntegrity
    PAGE:0000000140799EBB 4C 8D 05 DE 39 48 00   lea     r8, SeCiCallbacks
    PAGE:0000000140799EC2 8B CF                  mov     ecx, edi
    PAGE:0000000140799EC4 48 FF 15 95 71 99 FF   call    cs:__imp_CiInitialize
    */
    auto CiInitializeCall = FIND_PATTERN(PageBase, PageSize, "\x4C\x8D\x05\xCC\xCC\xCC\xCC\x8B\xCF");
    ASSERT(CiInitializeCall != nullptr);

    // Change CodeIntegrityOptions to zero for CiInitialize call
    *RVA<uint16_t*>(CiInitializeCall, 7) = 0xC931; // xor ecx, ecx

    /*
    nt!SeValidateImageData
    PAGE:00000001406EBD15                  loc_1406EBD15:
    PAGE:00000001406EBD15 48 83 C4 48            add     rsp, 48h
    PAGE:00000001406EBD19 C3                     retn
    PAGE:00000001406EBD1A CC                     db 0CCh
    PAGE:00000001406EBD1B                  loc_1406EBD1B:
    PAGE:00000001406EBD1B B8 28 04 00 C0         mov     eax, 0C0000428h
    PAGE:00000001406EBD20 EB F3                  jmp     short loc_1406EBD15
    PAGE:00000001406EBD20                  SeValidateImageData endp
    */
    auto SeValidateImageDataRet = FIND_PATTERN(PageBase, PageSize, "\x48\x83\xC4\x48\xC3\xCC\xB8\x28\x04\x00\xC0");
    ASSERT(SeValidateImageDataRet != nullptr);

    // Ensure SeValidateImageData returns a success status
    *RVA<uint32_t*>(SeValidateImageDataRet, 7) = 0; // mov eax, 0

    /*
    nt!SeCodeIntegrityQueryInformation
    PAGE:00000001406FFB30 48 83 EC 38                             sub     rsp, 38h
    PAGE:00000001406FFB34 48 83 3D BC DD 51 00 00                 cmp     cs:qword_140C1D8F8, 0
    PAGE:00000001406FFB3C 4D 8B C8                                mov     r9, r8
    PAGE:00000001406FFB3F 4C 8B D1                                mov     r10, rcx
    PAGE:00000001406FFB42 74 2F                                   jz      short loc_1406FFB73
    */
    auto SeCodeIntegrityQueryInformation = FIND_PATTERN(PageBase, PageSize, "\x48\x83\xEC\xCC\x48\x83\x3D\xCC\xCC\xCC\xCC\x00\x4D\x8B\xC8\x4C\x8B\xD1\x74");
    ASSERT(SeCodeIntegrityQueryInformation != nullptr);

    /*
    mov dword ptr [r8], 8
    xor eax, eax
    mov dword ptr [rcx+4], 1
    ret
    */
    memcpy(SeCodeIntegrityQueryInformation, "\x41\xC7\x00\x08\x00\x00\x00\x33\xC0\xC7\x41\x04\x01\x00\x00\x00\xC3", 17);
}

void PatchNtoskrnl(void* ImageBase, uint64_t ImageSize)
{
    // These patch locations are the same as EfiGuard:
    // https://github.com/Mattiwatti/EfiGuard/blob/25bb182026d24944713e36f129a93d08397de913/EfiGuardDxe/PatchNtoskrnl.c
    DisablePatchGuard(ImageBase, ImageSize);
    DisableDSE(ImageBase, ImageSize);
}