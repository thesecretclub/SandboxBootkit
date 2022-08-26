#include "Efi.hpp"

EFI_BOOT_SERVICES* gBS;
EFI_HANDLE gImageHandle;

EFI_GUID gEfiSimpleFileSystemProtocolGuid = { 0x964E5B22, 0x6459, 0x11D2, { 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B } };

void InitializeGlobals(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable)
{
	gImageHandle = ImageHandle;
	gBS = SystemTable->BootServices;
}