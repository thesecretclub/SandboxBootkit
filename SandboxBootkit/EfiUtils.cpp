#include <algorithm>

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
    // Check if relocations are already applied to the image
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
                auto RelocPtr = RVA<uint64_t*>(ImageBase, RelocRva);

                if (RelocType == EFI_IMAGE_REL_BASED_DIR64)
                {
                    *RelocPtr += ImageBaseDelta;
                }
                else
                {
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

struct RUNTIME_FUNCTION
{
    uint32_t BeginAddress;
    uint32_t EndAddress;
    uint32_t UnwindInfo;
};

#define RUNTIME_FUNCTION_INDIRECT 0x1

uint8_t* FindFunctionStart(void* ImageBase, void* Address)
{
    auto NtHeaders = GetNtHeaders(ImageBase);
    if (NtHeaders == nullptr)
    {
        return nullptr;
    }

    auto ExceptionDirectory = &NtHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (ExceptionDirectory->VirtualAddress == 0 || ExceptionDirectory->Size == 0)
    {
        return nullptr;
    }

    // Do a binary search to find the RUNTIME_FUNCTION
    auto Rva = (uint32_t)((uint8_t*)Address - (uint8_t*)ImageBase);
    auto Begin = RVA<RUNTIME_FUNCTION*>(ImageBase, ExceptionDirectory->VirtualAddress);
    auto End = Begin + ExceptionDirectory->Size / sizeof(RUNTIME_FUNCTION);
    auto FoundEntry = std::lower_bound(Begin, End, Rva, [](const RUNTIME_FUNCTION& Entry, uint32_t Rva)
        {
            return Entry.EndAddress < Rva;
        });

    // Make sure the found entry is in-range
    // See: https://en.cppreference.com/w/cpp/algorithm/lower_bound
    if (FoundEntry == End || Rva < FoundEntry->BeginAddress)
    {
        return nullptr;
    }

    // Resolve indirect function entries back to the owning entry
    // See: https://github.com/dotnet/runtime/blob/d5e3a5c2ca46691d65c81d520cb95f13f7a94652/src/coreclr/vm/codeman.cpp#L4403-L4416
    // As a sidenote, this seems to be why functions addresses have to be aligned?
    if ((FoundEntry->UnwindInfo & RUNTIME_FUNCTION_INDIRECT) != 0)
    {
        auto OwningEntryRva = FoundEntry->UnwindInfo - RUNTIME_FUNCTION_INDIRECT;
        FoundEntry = RVA<RUNTIME_FUNCTION*>(ImageBase, OwningEntryRva);
    }

    return RVA<uint8_t*>(ImageBase, FoundEntry->BeginAddress);
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
