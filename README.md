# SandboxBootkit

Bootkit tested on [Windows Sandbox](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-sandbox/windows-sandbox-overview) to patch `ntoskrnl.exe` and disable DSE/PatchGuard.

## Getting started

- Download the [latest release](https://github.com/thesecretclub/SandboxBootkit/releases/latest) and extract the archive;
- Run `Installer.exe`;
- Start Windows Sandbox.

**Note**: (parts of) the release might be detected as a virus by Windows Defender. This is a false positive, so you might need to add an exclusion.

## Standalone bootkit

You can run `SandbotBootkit.efi` on real hardware (untested) or a VM too (although you might as well use [EfiGuard](https://github.com/Mattiwatti/EfiGuard) in that case). To do so you attach a new (virtual) disk (formatted as FAT32) and copy `SandboxBootkit.efi` to `\EFI\Boot\bootx64.efi`. Then change the boot order to boot from your new disk first. The relevant functionality is implemented in the `LoadBootManager` function.

## Development

- Clone the project (with submodules);
- Use `SandboxBootkit.sln` to build the project;
- Look at the `Installer` project on how to install the bootkit.

**Note**: For development mode it's easiest to use `CmDiag DevelopmentMode -On` because without it you won't be able to write to `BaseLayer`.
