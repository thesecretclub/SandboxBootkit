#pragma once

#include "Efi.hpp"

void PatchReturn0(void* Function);
void PatchNtoskrnl(void* ImageBase, uint64_t ImageSize);