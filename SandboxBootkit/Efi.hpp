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

extern "C" EFI_IMAGE_DOS_HEADER __ImageBase;

extern EFI_HANDLE gImageHandle;
extern EFI_SYSTEM_TABLE* gST;
extern EFI_BOOT_SERVICES* gBS;
extern EFI_DEVICE_PATH_UTILITIES_PROTOCOL* gDevicePathLibDevicePathUtilities;

void InitializeGlobals(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable);

typedef EFI_STATUS (*BlImgLoadPEImageEx_t)(void*, void*, wchar_t*, void**, uint64_t*, void*, void*, void*, void*, void*, void*, void*, void*, void*);
