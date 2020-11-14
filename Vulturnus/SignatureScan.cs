using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Vulturnus
{
    public class SignatureScan
    {
        public List<byte> ByteArray { get; }
        public List<byte> Mask { get; }
        public string Pattern { get; }
        public ulong MemoryStart { get; }
        public uint MemorySize { get; }
        public byte[] VirtualMemory { get; }
        public uint Result { set; get; }
        public int PatternSize { get; }

        public SignatureScan(Process target, string pattern, ulong memoryStart, uint memorySize, uint result = 1)
        {
            ByteArray = new List<byte>();
            Mask = new List<byte>();
            Pattern = pattern;
            MemoryStart = memoryStart;
            MemorySize = memorySize;
            VirtualMemory = new Vulturnus(target).ReadVirtualMemory(memoryStart, memorySize);
            Result = result;
            PatternSize = 0;

            if (!string.IsNullOrEmpty(Pattern))
            {
                Pattern = Pattern.Replace(" ? ", " ?? ");

                while (Pattern.EndsWith(" ") || Pattern.EndsWith("?"))
                {
                    Pattern = Pattern.Substring(0, Pattern.Length - 1);
                }

                pattern = Pattern.Replace(" ", "");

                if (pattern.Length % 2 == 0 && pattern.Length > 0)
                {
                    PatternSize = pattern.Length / 2;

                    for (int i = 0; i < pattern.Length; i += 2)
                    {
                        if (pattern[i] == '?' && pattern[i + 1] == '?')
                        {
                            Mask.Add(1);
                            ByteArray.Add(0);
                        }
                        else
                        {
                            Mask.Add(0);
                            ByteArray.Add(Convert.ToByte(pattern[i].ToString() + pattern[i + 1].ToString(), 16));
                        }
                    }
                }
            }
        }

        public ulong Address()
        {
            uint k = 1;

            for (int i = 0; i < VirtualMemory.Length; ++i)
            {
                int j = 0;
                while (j < PatternSize && (Mask[j] == 0x01 || (VirtualMemory[i + j] ^ ByteArray[j]) == 0))
                {
                    ++j;
                }

                if (j == PatternSize)
                {
                    if (k == Result)
                    {
                        return MemoryStart + (ulong)i;
                    }

                    ++k;
                }
            }

            return ulong.MaxValue;
        }
    }
}

