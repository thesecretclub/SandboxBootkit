#include "Efi.hpp"

EFI_HANDLE gImageHandle;
EFI_SYSTEM_TABLE* gST;
EFI_BOOT_SERVICES* gBS;

EFI_GUID gEfiSimpleFileSystemProtocolGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
EFI_GUID gEfiLoadedImageProtocolGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
EFI_GUID gEfiDevicePathProtocolGuid = EFI_DEVICE_PATH_PROTOCOL_GUID;
EFI_GUID gEfiDevicePathUtilitiesProtocolGuid = EFI_DEVICE_PATH_UTILITIES_PROTOCOL_GUID;

void EfiInitializeGlobals(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable)
{
    gImageHandle = ImageHandle;
    gST = SystemTable;
    gBS = SystemTable->BootServices;
}

EFI_STATUS EfiFileDevicePath(EFI_HANDLE Device, const wchar_t* FileName, EFI_DEVICE_PATH** NewDevicePath)
{
    // Get the device path utils
    EFI_DEVICE_PATH_UTILITIES_PROTOCOL* DevicePathUtils = nullptr;
    auto Status = gBS->LocateProtocol(
        &gEfiDevicePathUtilitiesProtocolGuid,
        nullptr,
        (void**)&DevicePathUtils);
    if (EFI_ERROR(Status))
    {
        return Status;
    }

    // Query the device's device path
    EFI_DEVICE_PATH* DevicePath = nullptr;
    Status = gBS->HandleProtocol(Device, &gEfiDevicePathProtocolGuid, (void**)&DevicePath);
    if (EFI_ERROR(Status))
    {
        return Status;
    }

    // Allocate a file path
    auto FileNameSize = (wcslen(FileName) + 1) * sizeof(wchar_t);
    auto FilePathSize = FileNameSize + SIZE_OF_FILEPATH_DEVICE_PATH;

    FILEPATH_DEVICE_PATH* FilePath = nullptr;
    Status = gBS->AllocatePool(EfiBootServicesData, FilePathSize + sizeof(EFI_DEVICE_PATH), (void**)&FilePath);

    if (EFI_ERROR(Status))
    {
        return Status;
    }

    // Setup file path node
    FilePath->Header.Type = MEDIA_DEVICE_PATH;
    FilePath->Header.SubType = MEDIA_FILEPATH_DP;
    FilePath->Header.Length[0] = (uint8_t)(FilePathSize & 0xFF);
    FilePath->Header.Length[1] = (uint8_t)(FilePathSize >> 8);
    memcpy(FilePath->PathName, FileName, FileNameSize);

    // Create the end path node
    auto EndPath = RVA<EFI_DEVICE_PATH*>(FilePath, FilePathSize);
    EndPath->Type = END_DEVICE_PATH_TYPE;
    EndPath->SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE;
    EndPath->Length[0] = (uint8_t)sizeof(EFI_DEVICE_PATH);
    EndPath->Length[1] = 0;

    // Append the file path to the device path
    auto NewPath = DevicePathUtils->AppendDevicePath(DevicePath, (EFI_DEVICE_PATH*)FilePath);
    gBS->FreePool(FilePath);

    if (NewPath == nullptr)
    {
        return EFI_NOT_FOUND;
    }

    // Store the new device path
    *NewDevicePath = NewPath;

    return EFI_SUCCESS;
}

EFI_STATUS EfiQueryDevicePath(const wchar_t* FilePath, EFI_DEVICE_PATH** OutDevicePath)
{
    EFI_DEVICE_PATH* DevicePath = nullptr;

    // Get filesystem handles
    size_t Count = 0;
    EFI_HANDLE* Handles = nullptr;
    auto Status =
        gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &Count, &Handles);
    if (EFI_ERROR(Status))
    {
        return Status;
    }

    // Enumerate filesystem handles until buffer is valid
    for (size_t i = 0; i < Count && (DevicePath == nullptr); i++)
    {
        auto Handle = Handles[i];

        // Open the filesystem
        EFI_FILE_IO_INTERFACE* FileSystem = nullptr;
        Status = gBS->OpenProtocol(
            Handle, &gEfiSimpleFileSystemProtocolGuid, (void**)&FileSystem, gImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (EFI_ERROR(Status))
        {
            continue;
        }

        // Open the volume
        EFI_FILE_HANDLE Volume = nullptr;
        Status = FileSystem->OpenVolume(FileSystem, &Volume);
        if (!EFI_ERROR(Status))
        {
            // Open the file path
            EFI_FILE_HANDLE File = nullptr;
            Status = Volume->Open(Volume, &File, (CHAR16*)FilePath, EFI_FILE_MODE_READ, 0);
            if (!EFI_ERROR(Status))
            {
                // Create a device path for the file
                Status = EfiFileDevicePath(Handle, FilePath, &DevicePath);
                if (!EFI_ERROR(Status))
                {
                    // Store the result
                    *OutDevicePath = DevicePath;
                }
                else
                {
                    DevicePath = nullptr;
                }

                File->Close(File);
            }

            Volume->Close(Volume);
        }

        gBS->CloseProtocol(Handle, &gEfiSimpleFileSystemProtocolGuid, gImageHandle, nullptr);
    }

    gBS->FreePool(Handles);

    return Status;
}

void* EfiRelocateImage(void* ImageBase)
{
    // Get the headers
    auto NtHeaders = GetNtHeaders(ImageBase);

    if (NtHeaders == nullptr)
    {
        return nullptr;
    }

    // Allocate a new image buffer
    auto ImageSize = (size_t)NtHeaders->OptionalHeader.SizeOfImage;

    EFI_PHYSICAL_ADDRESS NewAddress = 0;
    auto Status = gBS->AllocatePages(AllocateAnyPages, EfiBootServicesCode, EFI_SIZE_TO_PAGES(ImageSize), &NewAddress);

    if (EFI_ERROR(Status))
    {
        return nullptr;
    }

    // Copy the image data
    void* NewImageBase = (void*)NewAddress;

    memcpy(NewImageBase, ImageBase, ImageSize);

    return NewImageBase;
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
