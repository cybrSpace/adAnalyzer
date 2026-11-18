using System;
using System.IO;
using System.Text;

namespace ADAnalyzer
{
    public static class JsonTextDecoder
    {
        public static string Decode(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                return String.Empty;
            }

            Encoding encoding;
            int offset = 0;

            // The little-endian UTF-32 preamble starts with the UTF-16 preamble.
            if (bytes.Length >= 4 &&
                bytes[0] == 0xFF && bytes[1] == 0xFE && bytes[2] == 0 && bytes[3] == 0)
            {
                encoding = new UTF32Encoding(false, false, true);
                offset = 4;
            }
            else if (bytes.Length >= 4 &&
                bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0xFE && bytes[3] == 0xFF)
            {
                encoding = new UTF32Encoding(true, false, true);
                offset = 4;
            }
            else if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
            {
                encoding = new UnicodeEncoding(false, false, true);
                offset = 2;
            }
            else if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
            {
                encoding = new UnicodeEncoding(true, false, true);
                offset = 2;
            }
            else
            {
                encoding = new UTF8Encoding(false, true);
                if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
                {
                    offset = 3;
                }
            }

            try
            {
                return encoding.GetString(bytes, offset, bytes.Length - offset);
            }
            catch (DecoderFallbackException)
            {
                // The runtime exception can include bytes from the input.
                throw new InvalidDataException("JSON input contains invalid encoded text.");
            }
        }
    }
}
