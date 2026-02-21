/*
Technitium Library
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;

namespace TechnitiumLibrary.IO
{
    public static class BinaryReaderExtensions
    {
        public static byte[] ReadBuffer(this BinaryReader bR)
        {
            return bR.ReadBytes(ReadLength(bR));
        }

        /// <summary>
        /// Read short string decoded as Length + byte[] ASSUMING its byte-length is strictly less than 256.
        /// Default UTF8 encoding is used.
        /// </summary>
        /// <param name="bR"></param>
        public static string ReadShortString(this BinaryReader bR)
        {
            return ReadShortString(bR, Encoding.UTF8);
        }

        /// <summary>
        /// Read short string decoded as Length + byte[] ASSUMING its byte-length is strictly less than 256.
        /// Method uses provided encoding.
        /// </summary>
        /// <param name="bR"></param>
        /// <param name="encoding"></param>
        public static string ReadShortString(this BinaryReader bR, Encoding encoding)
        {
            return encoding.GetString(bR.ReadBytes(bR.ReadByte()));
        }

        /// <summary>
        /// Read 8 bytes from the stream and interpret them
        /// as Unix timestamp in milliseconds from UnixEpoch
        /// </summary>
        /// <param name="bR"></param>
        /// <returns>DateTime is always in UTC</returns>
        public static DateTime ReadDateTime(this BinaryReader bR)
        {
            // Millisecond in C# ticks
            const long MillisecondAsTicks = 10_000;

            long ts_utc_ms = bR.ReadInt64();
            return new DateTime(DateTime.UnixEpoch.Ticks + ts_utc_ms * MillisecondAsTicks, DateTimeKind.Utc);
        }

        public static int ReadLength(this BinaryReader bR)
        {
            int length1 = bR.ReadByte();
            if (length1 > 127)
            {
                int numberLenBytes = length1 & 0x7F;
                if (numberLenBytes > 4)
                    throw new IOException("BinaryReaderExtension encoding length not supported.");

                Span<byte> valueBytes = stackalloc byte[4];
                bR.BaseStream.ReadExactly(valueBytes.Slice(4 - numberLenBytes, numberLenBytes));

                return BinaryPrimitives.ReadInt32BigEndian(valueBytes);
            }
            else
            {
                return length1;
            }
        }
    }
}
