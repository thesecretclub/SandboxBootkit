#include "EfiUtils.hpp"

EFI_IMAGE_NT_HEADERS64* GetNtHeaders(void* ImageBase)
{
    if (ImageBase == nullptr)
    {
        return nullptr;
    }

    auto DosHeader = (EFI_IMAGE_DOS_HEADER*)ImageBase;

    if (DosHeader->e_magic != EFI_IMAGE_DOS_SIGNATURE)
    {
        return nullptr;
    }

    auto NtHeaders = RVA<EFI_IMAGE_NT_HEADERS64*>(ImageBase, DosHeader->e_lfanew);

    if (NtHeaders->Signature != EFI_IMAGE_NT_SIGNATURE)
    {
        return nullptr;
    }

    return NtHeaders;
}

void* FindImageBase(uint64_t Address, size_t MaxSize)
{
    void* ImageBase = nullptr;

    // Align by page boundary
    Address &= ~(EFI_PAGE_SIZE - 1);

    // Determinate base address
    for (size_t Size = 0; Size < MaxSize && Address > 0; Size++)
    {
        if (GetNtHeaders((void*)Address) != nullptr)
        {
            ImageBase = (void*)Address;

            break;
        }

        Address -= EFI_PAGE_SIZE;
    }

    return ImageBase;
}

void* GetExport(void* ImageBase, const char* FunctionName, const char* ModuleName)
{
    auto NtHeaders = GetNtHeaders(ImageBase);

    if (NtHeaders == nullptr)
    {
        return nullptr;
    }

    auto DataDir =
        &NtHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (DataDir->VirtualAddress == 0 || DataDir->Size == 0)
    {
        return nullptr;
    }

    auto ExportDir = RVA<EFI_IMAGE_EXPORT_DIRECTORY*>(ImageBase, DataDir->VirtualAddress);
    auto ExportModuleName = RVA<char*>(ImageBase, ExportDir->Name);

    if (ModuleName != nullptr && Fnv1a(ExportModuleName) != Fnv1a(ModuleName))
    {
        return nullptr;
    }

    auto ExportNames = RVA<uint32_t*>(ImageBase, ExportDir->AddressOfNames);

    for (uint32_t i = 0; i < ExportDir->NumberOfNames; ++i)
    {
        auto ExportFunctionName = RVA<char*>(ImageBase, ExportNames[i]);

        if (Fnv1a(ExportFunctionName) == Fnv1a(FunctionName))
        {
            auto ExportFuncs = RVA<uint32_t*>(ImageBase, ExportDir->AddressOfFunctions);
            auto ExportOrds = RVA<uint16_t*>(ImageBase, ExportDir->AddressOfNameOrdinals);

            return RVA<void*>(ImageBase, ExportFuncs[ExportOrds[i]]);
        }
    }

    return nullptr;
}

bool ComparePattern(uint8_t* Base, uint8_t* Pattern, size_t PatternLen)
{
    for (; PatternLen; ++Base, ++Pattern, PatternLen--)
    {
        if (*Pattern != 0xCC && *Base != *Pattern)
        {
            return false;
        }
    }

    return true;
}

uint8_t* FindPattern(uint8_t* Base, size_t Size, uint8_t* Pattern, size_t PatternLen)
{
    Size -= PatternLen;

    for (size_t i = 0; i <= Size; ++i)
    {
        auto Address = &Base[i];

        if (ComparePattern(Address, Pattern, PatternLen))
        {
            return Address;
        }
    }

    return nullptr;
}

void Die()
{
    // At least one of these should kill the VM
    __fastfail(1);
    __int2c();
    __ud2();
    *(uint8_t*)0xFFFFFFFFFFFFFFFFull = 1;
}

EFI_STATUS GetFileDevicePath(EFI_HANDLE Device, const wchar_t* FileName, EFI_DEVICE_PATH** NewDevicePath)
{
    // Query the device's device path
    EFI_DEVICE_PATH* DevicePath = nullptr;
    auto Status = gBS->HandleProtocol(Device, &gEfiDevicePathProtocolGuid, (void**)&DevicePath);
    if (EFI_ERROR(Status))
    {
        return Status;
    }

    // Allocate a file path
    auto FileNameSize = wcslen(FileName) * sizeof(wchar_t);
    auto FilePathSize = FileNameSize + sizeof(EFI_DEVICE_PATH);

    FILEPATH_DEVICE_PATH* FilePath = nullptr;
    Status = gBS->AllocatePool(EfiBootServicesData, FileNameSize, (void**)&FilePath);

    if (EFI_ERROR(Status))
    {
        return Status;
    }

    // Setup file path using file name
    FilePath->Header.Type = MEDIA_DEVICE_PATH;
    FilePath->Header.SubType = MEDIA_FILEPATH_DP;
    FilePath->Header.Length[0] = (uint8_t)(FilePathSize & 0xFF);
    FilePath->Header.Length[1] = (uint8_t)(FilePathSize >> 8);
    memcpy(FilePath->PathName, FileName, FileNameSize);

    // Append the file path to the device path
    auto ImgPath = gDevicePathLibDevicePathUtilities->AppendDeviceNode(DevicePath, (EFI_DEVICE_PATH*)FilePath);
    gBS->FreePool(FilePath);

    if (ImgPath == nullptr)
    {
        return EFI_NOT_FOUND;
    }

    // Store the new device path
    *NewDevicePath = ImgPath;

    return EFI_SUCCESS;
}

EFI_STATUS QueryDevicePath(const wchar_t* FilePath, EFI_DEVICE_PATH** OutDevicePath)
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
                Status = GetFileDevicePath(Handle, FilePath, &DevicePath);
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
