#pragma once

// Modified version for C++ compatibility
#include "ProcessorBind.hpp"

extern "C"
{
#include <Uefi.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
#include <IndustryStandard/PeImage.h>
}

extern EFI_BOOT_SERVICES* gBS;
extern EFI_HANDLE gImageHandle;

void InitializeGlobals(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable);