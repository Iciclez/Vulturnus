using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Vulturnus
{
    public enum PaddingByte : byte
    {
        NOP = 0x90,
        INT3 = 0xCC
    }

    public class Vulturnus
    {
        public Process TargetProcess { get; }
        public PaddingByte Padding { get; set; }
        private Dictionary<ulong, byte[]> MemoryPatches { get; }

        private Func<ulong, uint, Action, bool> PageExecuteReadWrite;


        [StructLayout(LayoutKind.Sequential)]
        protected struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public Protection Protect;
            public uint Type;
        }

        public enum Protection : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        [DllImport("kernel32.dll")]
        protected static extern uint VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll")]
        protected static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        protected static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        protected static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, uint dwSize, out IntPtr lpNumberOfBytesRead);

        public Vulturnus(Process target, PaddingByte padding = PaddingByte.NOP)
        {
            TargetProcess = target;
            Padding = padding;
            MemoryPatches = new Dictionary<ulong, byte[]>();

            PageExecuteReadWrite = (address, size, function) =>
            {
                Func<ulong, bool> PageHasExecuteReadWriteAccess = (queryAddress) =>
                {
                    MEMORY_BASIC_INFORMATION information = new MEMORY_BASIC_INFORMATION();

                    if (VirtualQueryEx(TargetProcess.Handle, (IntPtr)queryAddress, out information, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)))
                    {
                        return false;
                    }

                    if (information.Protect == 0 || ((information.Protect & Protection.PAGE_GUARD) != 0))
                    {
                        return false;
                    }

                    if ((information.Protect & Protection.PAGE_EXECUTE_READWRITE) == 0)
                    {
                        return false;
                    }

                    return true;
                };

                uint protect = 0;

                if (!PageHasExecuteReadWriteAccess(address))
                {
                    protect = VirtualProtectEx(TargetProcess.Handle, (IntPtr)address, size, (uint)Protection.PAGE_EXECUTE_READWRITE, out protect) ? protect : 0;
                }

                function();

                if (protect != 0)
                {
                    return VirtualProtectEx(TargetProcess.Handle, (IntPtr)address, size, protect, out protect);
                }

                return true;
            };
        }

        public byte[] ReadVirtualMemory(ulong address, uint size)
        {
            byte[] memory = new byte[size];

            PageExecuteReadWrite(address, size, () =>
            {
                IntPtr numberOfBytesRead = new IntPtr();
                ReadProcessMemory(TargetProcess.Handle, (IntPtr)address, memory, size, out numberOfBytesRead);
            });

            return memory;
        }

        public bool WriteVirtualMemory(ulong address, string arrayOfBytes, uint paddingSize = 0, bool retainBytes = true)
        {
            arrayOfBytes = arrayOfBytes.Replace(" ", "");

            if (arrayOfBytes.Length == 0 || arrayOfBytes.Length % 2 == 1)
            {
                return false;
            }

            List<byte> bytes = new List<byte>();

            for (int i = 0; i < arrayOfBytes.Length; i += 2)
            {
                bytes.Add(Convert.ToByte(new string(new char[] { arrayOfBytes[i], arrayOfBytes[i + 1] }), 16));
            }

            return WriteVirtualMemory(address, bytes, paddingSize, retainBytes);
        }

        public bool WriteVirtualMemory(ulong address, byte[] arrayOfBytes, bool retainBytes = true)
        {
            return PageExecuteReadWrite(address, (uint)arrayOfBytes.Length, () =>
            {
                if (retainBytes)
                {
                    MemoryPatches.Add(address, ReadVirtualMemory(address, (uint)arrayOfBytes.Length));
                }

                IntPtr numberOfBytesWritten = new IntPtr();
                WriteProcessMemory(TargetProcess.Handle, (IntPtr)address, arrayOfBytes, (uint)arrayOfBytes.Length, out numberOfBytesWritten);
            });
        }

        public bool WriteVirtualMemory(ulong address, List<byte> listOfBytes, uint paddingSize = 0, bool retainBytes = true)
        {
            for (uint i = 0; i < paddingSize; ++i)
            {
                listOfBytes.Add((byte)Padding);
            }

            return WriteVirtualMemory(address, listOfBytes.ToArray(), retainBytes);
        }

        public bool RevertVirtualMemory(ulong address)
        {
            if (MemoryPatches.ContainsKey(address))
            {
                return WriteVirtualMemory(address, MemoryPatches[address], false);
            }

            return false;
        }
    }
}
