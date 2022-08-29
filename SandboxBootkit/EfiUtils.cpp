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

bool FixRelocations(void* ImageBase, uint64_t ImageBaseDelta)
{
    if (ImageBaseDelta == 0)
    {
        return true;
    }

    auto NtHeaders = GetNtHeaders(ImageBase);
    if (NtHeaders == nullptr)
    {
        return false;
    }

    auto DataDir =
        &NtHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (DataDir->VirtualAddress == 0 || DataDir->Size == 0)
    {
        return true;
    }

    auto BaseReloc =
        RVA<EFI_IMAGE_BASE_RELOCATION*>(ImageBase, DataDir->VirtualAddress);
    auto RelocsSize = DataDir->Size;

    while (RelocsSize > 0 && BaseReloc->SizeOfBlock)
    {
        auto NumberOfRelocs = (BaseReloc->SizeOfBlock - EFI_IMAGE_SIZEOF_BASE_RELOCATION) / sizeof(uint16_t);
        auto Relocs = RVA<uint16_t*>(BaseReloc, 8);

        for (size_t i = 0; i < NumberOfRelocs; i++)
        {
            auto Reloc = Relocs[i];
            if (Reloc != 0)
            {
                auto RelocType = (Reloc & 0xF000) >> 12;
                auto RelocRva = BaseReloc->VirtualAddress + (Reloc & 0xFFF);
                auto RelocPtr = RVA<char*>(ImageBase, RelocRva);

                switch (RelocType)
                {
                case EFI_IMAGE_REL_BASED_ABSOLUTE:
                    break;
                case EFI_IMAGE_REL_BASED_HIGH:
                    (*(uint16_t*)RelocPtr) += HIWORD(((uint16_t)ImageBaseDelta));
                    break;
                case EFI_IMAGE_REL_BASED_LOW:
                    (*(uint16_t*)RelocPtr) += LOWORD(((uint16_t)ImageBaseDelta));
                    break;
                case EFI_IMAGE_REL_BASED_HIGHLOW:
                    (*(uint32_t*)RelocPtr) += ((uint32_t)ImageBaseDelta);
                    break;
                case EFI_IMAGE_REL_BASED_DIR64:
                    (*(uint64_t*)RelocPtr) += ImageBaseDelta;
                    break;
                default:
                    return false;
                }
            }
        }

        BaseReloc =
            RVA<EFI_IMAGE_BASE_RELOCATION*>(BaseReloc, BaseReloc->SizeOfBlock);
        RelocsSize -= BaseReloc->SizeOfBlock;
    }

    return true;
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
