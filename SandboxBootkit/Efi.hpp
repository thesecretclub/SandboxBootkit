#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <intrin.h>

// Modified version for C++ compatibility
#include "ProcessorBind.hpp"

extern "C"
{
#ifdef NULL
#undef NULL
#endif
#include <Uefi.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePathUtilities.h>
#include <IndustryStandard/PeImage.h>
}

#include "EfiUtils.hpp"

extern "C" EFI_IMAGE_DOS_HEADER __ImageBase;

extern EFI_HANDLE gImageHandle;
extern EFI_SYSTEM_TABLE* gST;
extern EFI_BOOT_SERVICES* gBS;

void EfiInitializeGlobals(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable);
EFI_STATUS EfiFileDevicePath(EFI_HANDLE Device, const wchar_t* FileName, EFI_DEVICE_PATH** NewDevicePath);
EFI_STATUS EfiQueryDevicePath(const wchar_t* FilePath, EFI_DEVICE_PATH** OutDevicePath);
void* EfiRelocateImage(void* ImageBase);