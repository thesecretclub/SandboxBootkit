#include "Efi.hpp"

EFI_STATUS EFIAPI EfiEntry(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable)
{
	SystemTable->ConOut->OutputString(SystemTable->ConOut, L"Hello from CMake!\n");
	return EFI_SUCCESS;
}