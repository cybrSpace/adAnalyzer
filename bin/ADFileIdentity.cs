using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

namespace ADAnalyzer
{
    public static class MacFileIdentity
    {
        private const ushort AttrBitmapCount = 5;
        private const uint AttrCommonDeviceId = 0x00000002;
        private const uint AttrCommonFileId = 0x02000000;
        private const uint NoFollow = 1;
        private const int ResultSize = 16;
        private const int NoEntry = 2;
        private const int NotDirectory = 20;

        [StructLayout(LayoutKind.Sequential)]
        private struct AttributeList
        {
            public ushort BitmapCount;
            public ushort Reserved;
            public uint Common;
            public uint Volume;
            public uint Directory;
            public uint File;
            public uint Fork;
        }

        [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "getattrlist", SetLastError = true)]
        private static extern int GetAttributes(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
            ref AttributeList attributes,
            [Out] byte[] result,
            UIntPtr resultSize,
            UIntPtr options);

        public static bool IsSameEntry(string source, string destination)
        {
            int sourceDevice;
            ulong sourceId;
            int destinationDevice;
            ulong destinationId;
            return TryRead(source, out sourceDevice, out sourceId)
                && TryRead(destination, out destinationDevice, out destinationId)
                && sourceDevice == destinationDevice
                && sourceId == destinationId;
        }

        private static bool TryRead(string path, out int device, out ulong fileId)
        {
            var attributes = new AttributeList
            {
                BitmapCount = AttrBitmapCount,
                Common = AttrCommonDeviceId | AttrCommonFileId
            };
            var result = new byte[ResultSize];
            // Report publication replaces the final entry. Read metadata for that entry.
            if (GetAttributes(path, ref attributes, result, new UIntPtr(ResultSize), new UIntPtr(NoFollow)) != 0)
            {
                int error = Marshal.GetLastWin32Error();
                if (error == NoEntry || error == NotDirectory)
                {
                    device = 0;
                    fileId = 0;
                    return false;
                }

                throw new IOException(
                    "Could not verify the saved report destination identity.",
                    new Win32Exception(error));
            }

            // Darwin returns a length word followed by the requested fixed-size fields.
            if (BitConverter.ToUInt32(result, 0) != ResultSize)
            {
                throw new IOException("Could not verify the saved report destination identity.");
            }

            device = BitConverter.ToInt32(result, 4);
            fileId = BitConverter.ToUInt64(result, 8);
            return true;
        }
    }
}
