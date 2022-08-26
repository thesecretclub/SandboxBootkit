#include "Efi.hpp"

static EFI_HANDLE gEfiFileSystemHandle = nullptr;
static EFI_FILE_IO_INTERFACE* gEfiFileSystem = nullptr;

static EFI_STATUS FindEfiFileSystem()
{
	UINTN handleCount = 0;
	EFI_HANDLE* handles = nullptr;
	EFI_STATUS status = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, nullptr, &handleCount, &handles);
	if (!EFI_ERROR(status))
	{
		for (UINTN i = 0; i < handleCount; i++)
		{
			EFI_FILE_IO_INTERFACE* fileSystem = nullptr;
			status = gBS->OpenProtocol(handles[i], &gEfiSimpleFileSystemProtocolGuid, (void**)&fileSystem, gImageHandle, nullptr, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
			if (!EFI_ERROR(status))
			{
				EFI_FILE_HANDLE volume = nullptr;
				status = fileSystem->OpenVolume(fileSystem, &volume);
				if (!EFI_ERROR(status))
				{
					EFI_FILE_HANDLE file;
					status = volume->Open(volume, &file, L"\\EFI\\Microsoft\\Boot\\boot.stl", EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);
					if (!EFI_ERROR(status))
					{
						if (gEfiFileSystemHandle == nullptr)
						{
							gEfiFileSystemHandle = handles[i];
							gEfiFileSystem = fileSystem;
						}

						file->Close(file);
					}

					// Keeping a volume handle open hangs bootmgfw in BlpDeviceOpen
					volume->Close(volume);
				}

				// Keep a handle to the protocol for logging but close the rest
				if (gEfiFileSystemHandle != nullptr && handles[i] != gEfiFileSystemHandle)
				{
					gBS->CloseProtocol(handles[i], &gEfiSimpleFileSystemProtocolGuid, gImageHandle, NULL);
				}
			}
		}

		gBS->FreePool(handles);
	}

	return status;
}

EFI_STATUS EFIAPI EfiEntry(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable)
{
	InitializeGlobals(ImageHandle, SystemTable);

	SystemTable->ConOut->OutputString(SystemTable->ConOut, L"Hello from bootkit!\n");
	auto status = FindEfiFileSystem();
	if (EFI_ERROR(status))
	{
		return status;
	}

	// TODO: Use LoadImage/StartImage to load bootmgfw.efi.bak

	return EFI_SUCCESS;
}