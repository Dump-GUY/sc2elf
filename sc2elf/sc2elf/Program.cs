using CommandLine;
using CommandLine.Text;
using LibObjectFile.Elf;
using System.Diagnostics.CodeAnalysis;

namespace sc2elf
{
    internal class Program
    {
        public class Options
        {
            [Option('p', "path", Required = true, HelpText = "Path to shellcode file.")]
            public string? Path { get; set; }

            [Option('a', "architecture", Required = true, HelpText = "Architecture: 32 or 64 (depending on the shellcode).")]
            public uint? Architecture { get; set; }

            [Option('o', "offset", Required = false, Default = (uint)0, HelpText = "Optional. Start offset of the shellcode (default 0).")]
            public uint Offset { get; set; }

            [Usage(ApplicationAlias = "sc2elf")]
            public static IEnumerable<Example> Examples
            {
                get
                {
                    return new List<Example>()
                    {
                        new Example("Convert shellcode to 32-bit ELF (shellcode Start Offset set to 66th byte)", new Options { Path = "C:\\shellcode.bin", Architecture = 32, Offset = 66 })
                    };
                }
            }
        }

        static ElfObjectFile CreateELF64(string path, uint epOffset, ulong imageBase = 0x400000)
        {
            byte[] shellcode = File.ReadAllBytes(path);
            var codeStream = new MemoryStream();
            codeStream.Write(shellcode);

            var elf = new ElfObjectFile(ElfArch.X86_64);
            elf.FileType = ElfFileType.Executable;
            elf.EntryPointAddress = imageBase + epOffset;

            var codeSection = elf.AddSection(new ElfBinaryShadowSection()
            {
                Stream = codeStream,
                Alignment = 0x1000,
            });

            elf.AddSegment(new ElfSegment()
            {
                Type = ElfSegmentTypeCore.Load,
                Range = codeSection,
                VirtualAddress = imageBase,
                PhysicalAddress = imageBase,
                Flags = ElfSegmentFlagsCore.Readable | ElfSegmentFlagsCore.Writable | ElfSegmentFlagsCore.Executable,
                Size = (ulong)codeStream.Length,
                SizeInMemory = (ulong)codeStream.Length,
                Alignment = 0x1000,
            });

            return elf;
        }

        static ElfObjectFile CreateELF32(string path, uint epOffset, ulong imageBase = 0x8048000)
        {
            byte[] shellcode = File.ReadAllBytes(path);           
            var codeStream = new MemoryStream();
            codeStream.Write(shellcode);

            var elf = new ElfObjectFile(ElfArch.I386);
            elf.FileType = ElfFileType.Executable;
            elf.EntryPointAddress = imageBase + epOffset;

            var codeSection = elf.AddSection(new ElfBinaryShadowSection()
            {
                Stream = codeStream,
                Alignment = 0x1000,
            });

            elf.AddSegment(new ElfSegment()
            {
                Type = ElfSegmentTypeCore.Load,
                Range = codeSection,
                VirtualAddress = imageBase,
                PhysicalAddress = imageBase,
                Flags = ElfSegmentFlagsCore.Readable | ElfSegmentFlagsCore.Writable | ElfSegmentFlagsCore.Executable,
                Size = (ulong)codeStream.Length,
                SizeInMemory = (ulong)codeStream.Length,
                Alignment = 0x1000,
            });

            return elf;
        }

        [DynamicDependency(DynamicallyAccessedMemberTypes.All, typeof(Options))]
        static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args)
                  .WithParsed<Options>(o =>
                  {
                      if (!File.Exists(o.Path)) { Console.WriteLine($"Can´t find shellcode file: {o.Path}"); }

                      else
                      {
                          if (o.Architecture == 32)
                          {
                              var elf = CreateELF32(o.Path, o.Offset);
                              using var outStream = File.OpenWrite(o.Path + ".elf");
                              elf.Write(outStream);
                              Console.WriteLine($"ELF created: {o.Path + ".elf"}");
                          }
                          else if (o.Architecture == 64)
                          {
                              var elf = CreateELF64(o.Path, o.Offset);
                              using var outStream = File.OpenWrite(o.Path + ".elf");
                              elf.Write(outStream);
                              Console.WriteLine($"ELF created: {o.Path + ".elf"}");
                          }
                          else { Console.WriteLine($"Wrong architecture selected: {o.Architecture}"); }
                      }
                  });
        }
    }
}