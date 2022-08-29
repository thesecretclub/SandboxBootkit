#pragma once

static const size_t DetourSize = 12;
static const uint64_t Fnv1aValue = 0xCBF29CE484222325;
static const uint64_t Fnv1aPrime = 0x100000001B3;

inline uint64_t Fnv1a(const char* Str)
{
    auto Value = Fnv1aValue;
    auto Len = (Str != nullptr) ? strlen(Str) : 0;

    for (size_t i = 0; i < Len; i++)
    {
        Value ^= uint32_t((Str[i] >= 'A' && Str[i] <= 'Z') ? (Str[i] - ('A' - 'a')) : Str[i]);
        Value *= Fnv1aPrime;
    }

    return Value;
}

template<typename R, typename T>
R RVA(T Ptr, int64_t Offset)
{
    return (R)((uint64_t)Ptr + Offset);
}

template<typename Func>
void DetourCreate(Func* OriginalFunction, Func* HookFunction, uint8_t OriginalBytes[DetourSize])
{
    // Copy the function to the original bytes
    memcpy(OriginalBytes, OriginalFunction, DetourSize);

    // Create a 64-bit mov rax; jmp rax
    memcpy(OriginalFunction, "\x48\xB8\xEF\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xFF\xE0", DetourSize);

    // Overwrite rax to the hook function
    *RVA<void**>(OriginalFunction, 2) = HookFunction;
}

template<typename Func>
void DetourRestore(Func* OriginalFunction, uint8_t OriginalBytes[DetourSize])
{
    // Copy the original bytes to the function
    memcpy(OriginalFunction, OriginalBytes, DetourSize);
}

EFI_IMAGE_NT_HEADERS64* GetNtHeaders(void* ImageBase);
void* FindImageBase(uint64_t Address, size_t MaxSize = (1 * 1024 * 1024));
void* GetExport(void* ImageBase, const char* FunctionName, const char* ModuleName = nullptr);
bool FixRelocations(void* ImageBase, uint64_t ImageBaseDelta);
bool ComparePattern(uint8_t* Base, uint8_t* Pattern, size_t PatternLen);
uint8_t* FindPattern(uint8_t* Base, size_t Size, uint8_t* Pattern, size_t PatternLen);
void Die();

#define FIND_PATTERN(Base, Size, Pattern) FindPattern((uint8_t*)Base, Size, (uint8_t*)Pattern, ARRAY_SIZE(Pattern) - 1);
