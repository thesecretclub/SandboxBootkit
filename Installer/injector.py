# Based on: https://pmeerw.net/blog/programming/pefile-rewrite.html

#!/usr/env python3

import pefile
import sys
import os

def adjust_SectionSize(sz, align):
    if sz % align: sz = ((sz + align) // align) * align
    return sz

def main():
    if len(sys.argv) < 3:
        print("Usage: injector.py bootmgfw.efi.bak SandboxBootkit.efi")
        sys.exit(1)

    bootmgfw_file = sys.argv[1]
    bootkit_file = sys.argv[2]

    pe = pefile.PE(bootmgfw_file)
    bootkit_pe = pefile.PE(bootkit_file)
    # TODO: verify that we didn't already inject here (perhaps implement re-injection?)
    bootkit_entry_rva = bootkit_pe.OPTIONAL_HEADER.AddressOfEntryPoint
    # Put the original bootmgfw entry point in the bootkit entry point
    bootkit_pe.OPTIONAL_HEADER.AddressOfEntryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    bootkit_data = bootkit_pe.write()
    # TODO: verify that the image base is correct and calculate this alignment dynamically
    bootkit_alignment = 0x1000
    new_section_data = b"\xCC" * bootkit_alignment + bootkit_data

    last_section = pe.sections[-1]

    new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)

    # fill with zeros
    new_section.__unpack__(bytearray(new_section.sizeof()))

    # place section header after last section header (assume there is enough room)
    new_section.set_file_offset(last_section.get_file_offset() + last_section.sizeof())

    new_section.Name = b'.bootkit'
    new_section_size = len(new_section_data)

    new_section.SizeOfRawData = adjust_SectionSize(new_section_size, pe.OPTIONAL_HEADER.FileAlignment)
    # TODO: strip signature?
    new_section.PointerToRawData = len(pe.__data__)

    new_section.Misc = new_section.Misc_PhysicalAddress = new_section.Misc_VirtualSize = new_section_size
    new_section.VirtualAddress = last_section.VirtualAddress + adjust_SectionSize(last_section.Misc_VirtualSize, pe.OPTIONAL_HEADER.SectionAlignment)

    new_section.Characteristics = 0xE0000020 # rwx + code

    # TODO: save bootmgfw EP in FoxBoot.efi header

    # change address of entry point to beginning of new section
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_section.VirtualAddress + bootkit_alignment + bootkit_entry_rva

    # increase size of image
    pe.OPTIONAL_HEADER.SizeOfImage += adjust_SectionSize(new_section_size, pe.OPTIONAL_HEADER.SectionAlignment)

    # increase number of sections
    pe.FILE_HEADER.NumberOfSections += 1

    # append new section to structures
    pe.sections.append(new_section)
    pe.__structures__.append(new_section)

    # add new section data to file
    pe.__data__ = bytearray(pe.__data__) + new_section_data

    injected_path = os.path.join(os.path.dirname(bootkit_file), "bootmgfw.efi")
    pe.write(injected_path)
    print("Created injected bootmgfw.efi")

if __name__ == "__main__":
    main()
