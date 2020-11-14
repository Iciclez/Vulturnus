using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace Vulturnus.Test
{
    class Program
    {
        public static void TestInjector()
        {
            Inject injector = new Inject(Process.GetProcessesByName("Icy.Test").ToList(), InjectionRoutine.LoadLibraryW);

            injector.InjectLibrary(new List<string> { @"C:\Projects\Ryupdate\Release\Ryupdate.dll" });
        }

        public static void TestVulturnus(ulong address)
        {
            Vulturnus vulturnus = new Vulturnus(Process.GetProcessesByName("Icy.Test")[0]);

            var v = vulturnus.ReadVirtualMemory(address, 10);
            foreach (var n in v)
            {
                Console.Write("{0:X} ", n);
            }

            Console.WriteLine();

            //vulturnus.WriteVirtualMemory(0x00584F87, new List<byte>{ 0x33, 0x33, 0x33, 0xCC, 0xCC, 0xCC }, 2);

            vulturnus.WriteVirtualMemory(address, "33 CC 33 CC 33 CC", 2);


            v = vulturnus.ReadVirtualMemory(address, 10);
            foreach (var n in v)
            {
                Console.Write("{0:X} ", n);
            }

            Console.WriteLine();

            vulturnus.RevertVirtualMemory(address);

            v = vulturnus.ReadVirtualMemory(address, 10);
            foreach (var n in v)
            {
                Console.Write("{0:X} ", n);
            }
        }

        static void Main(string[] args)
        {
            TestInjector();
            TestVulturnus(0x00E94F87);
            SignatureScan signatureScan = new SignatureScan(Process.GetProcessesByName("Icy.Test")[0], "E8 ?? ? ?? ?? E9 ?? ?? ?? ?? 55 8B EC 6A 00 FF", 0x00e91000, 0x4000, 1);

            Console.WriteLine("{0:X}", signatureScan.Address());

            Console.ReadLine();
        }
    }
}
