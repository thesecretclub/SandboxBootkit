#pragma once

#include "Efi.hpp"

static constexpr size_t JmpSize = 12;
static constexpr uint64_t Const64Val = 0xcbf29ce484222325;
static constexpr uint64_t Const64Prime = 0x100000001b3;

inline constexpr uint64_t Fnv1a(const char* const Str, const uint64_t Value = Const64Val) noexcept
{
    return (Str[0] == '\0') ? Value : Fnv1a(&Str[1], (Value ^ uint32_t((Str[0] >= 'A' && Str[0] <= 'Z') ? Str[0] - ('A' - 'a') : Str[0])) * Const64Prime);
}

template<typename R, typename T>
R RVA(T Ptr, int64_t Offset)
{
    return (R)((uint64_t)Ptr + Offset);
}

template<typename Func>
void DetourCreate(Func* OriginalFunction, Func* HookFunction, uint8_t OriginalBytes[JmpSize])
{
    // Copy the function to the original bytes
    memcpy(OriginalBytes, OriginalFunction, JmpSize);

    // Create a 64-bit mov rax; jmp rax
    memcpy(OriginalFunction, "\x48\xB8\xEF\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xFF\xE0", JmpSize);

    // Overwrite rax to the hook function
    *RVA<void**>(OriginalFunction, 2) = HookFunction;
}

template<typename Func>
void DetourRestore(Func* OriginalFunction, uint8_t OriginalBytes[JmpSize])
{
    // Copy the original bytes to the function
    memcpy(OriginalFunction, OriginalBytes, JmpSize);
}

EFI_IMAGE_NT_HEADERS64* GetNtHeaders(void* ImageBase);
void* FindImageBase(uint64_t Address, size_t MaxSize = (1 * 1024 * 1024));
void* GetExport(void* ImageBase, const char* FunctionName, const char* ModuleName = nullptr);
bool ComparePattern(uint8_t* Base, uint8_t* Pattern, size_t PatternLen);
uint8_t* FindPattern(uint8_t* Base, size_t Size, uint8_t* Pattern, size_t PatternLen);
void Die();
EFI_STATUS QueryDevicePath(const wchar_t* FilePath, EFI_DEVICE_PATH** OutDevicePath);

#define FIND_PATTERN(Base, Size, Pattern) FindPattern((uint8_t*)Base, Size, (uint8_t*)Pattern, ARRAY_SIZE(Pattern) - 1);
