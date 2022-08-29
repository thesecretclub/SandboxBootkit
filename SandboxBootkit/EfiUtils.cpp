#include "Efi.hpp"

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
