#include "Efi.hpp"

EFI_HANDLE gImageHandle;
EFI_SYSTEM_TABLE* gST;
EFI_BOOT_SERVICES* gBS;
EFI_DEVICE_PATH_UTILITIES_PROTOCOL* gDevicePathLibDevicePathUtilities;

EFI_GUID gEfiSimpleFileSystemProtocolGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
EFI_GUID gEfiLoadedImageProtocolGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
EFI_GUID gEfiDevicePathProtocolGuid = EFI_DEVICE_PATH_PROTOCOL_GUID;
EFI_GUID gEfiDevicePathUtilitiesProtocolGuid = EFI_DEVICE_PATH_UTILITIES_PROTOCOL_GUID;

void InitializeGlobals(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable)
{
    gImageHandle = ImageHandle;
    gST = SystemTable;
    gBS = SystemTable->BootServices;

    gBS->LocateProtocol(
        &gEfiDevicePathUtilitiesProtocolGuid,
        nullptr,
        (void**)&gDevicePathLibDevicePathUtilities);
}

#pragma function(memcmp)
int memcmp(const void* Dest, const void* Source, size_t Size)
{
    int32_t Value = 0;
    uint8_t* Ptr1 = (uint8_t*)Dest;
    uint8_t* Ptr2 = (uint8_t*)Source;

    while (Size-- > 0 && Value == 0)
    {
        Value = *(Ptr1++) - *(Ptr2++);
    }

    return Value;
}

#pragma function(memcpy)
void* memcpy(void* Target, const void* Source, size_t Size)
{
    __movsb((uint8_t*)Target, (uint8_t*)Source, Size);

    return Target;
}

#pragma function(memset)
void* memset(void* Target, int32_t Value, size_t Size)
{
    __stosb((uint8_t*)Target, (uint8_t)Value, Size);

    return Target;
}
