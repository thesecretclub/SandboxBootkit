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
    nt!KiInitPGContextCaller
    INIT:0000000140A359E0 40 53                  push    rbx
    INIT:0000000140A359E2 48 83 EC 30            sub     rsp, 30h
    INIT:0000000140A359E6 8B 41 18               mov     eax, [rcx+18h]
    INIT:0000000140A359E9 48 8B D9               mov     rbx, rcx
    INIT:0000000140A359EC 4C 8B 49 10            mov     r9, [rcx+10h]
    INIT:0000000140A359F0 44 8B 41 08            mov     r8d, [rcx+8]
    INIT:0000000140A359F4 8B 51 04               mov     edx, [rcx+4]
    INIT:0000000140A359F7 8B 09                  mov     ecx, [rcx]
    INIT:0000000140A359F9 89 44 24 20            mov     [rsp+38h+var_18], eax
    INIT:0000000140A359FD E8 E2 54 FE FF         call    KiInitPGContext
    */
    auto KiInitPGContextCaller = FIND_PATTERN(InitBase, InitSize, "\x40\x53\x48\x83\xEC\x30\x8B\x41\x18");
    ASSERT(KiInitPGContextCaller != nullptr);

    // Force KiInitPGContext to return successful (this is the new patch)
    memcpy(RVA<void*>(KiInitPGContextCaller, 29), "\xB0\x01\x90\x90\x90", 5); // mov al, 1; nop x3

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
    // Many of these patches come from EfiGuard:
    // https://github.com/Mattiwatti/EfiGuard/blob/25bb182026d24944713e36f129a93d08397de913/EfiGuardDxe/PatchNtoskrnl.c
    DisablePatchGuard(ImageBase, ImageSize);
    DisableDSE(ImageBase, ImageSize);
}