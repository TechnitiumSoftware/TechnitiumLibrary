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
    public static class BinaryWriterExtensions
    {
        public static void WriteBuffer(this BinaryWriter bW, byte[] buffer, int offset, int count)
        {
            WriteLength(bW, count);
            bW.Write(buffer, offset, count);
        }

        public static void WriteBuffer(this BinaryWriter bW, byte[] buffer)
        {
            WriteLength(bW, buffer.Length);
            bW.Write(buffer, 0, buffer.Length);
        }

        public static void WriteShortString(this BinaryWriter bW, string value)
        {
            WriteShortString(bW, value, Encoding.UTF8);
        }

        public static void WriteShortString(this BinaryWriter bW, string value, Encoding encoding)
        {
            byte[] buffer = encoding.GetBytes(value);
            if (buffer.Length > 255)
                throw new ArgumentOutOfRangeException(nameof(value), "Parameter 'value' exceeded max length of 255 bytes.");

            bW.Write(Convert.ToByte(buffer.Length));
            bW.Write(buffer);
        }

        public static void Write(this BinaryWriter bW, DateTime date)
        {
            bW.Write(Convert.ToInt64((date.ToUniversalTime() - DateTime.UnixEpoch).TotalMilliseconds));
        }

        public static void WriteLength(this BinaryWriter bW, int valueLength)
        {
            if (valueLength < 128)
            {
                bW.Write((byte)valueLength);
            }
            else
            {
                Span<byte> bytesValueLength = stackalloc byte[4];
                BinaryPrimitives.WriteInt32BigEndian(bytesValueLength, valueLength);

                for (int i = 0; i < 4; i++)
                {
                    if (bytesValueLength[i] != 0)
                    {
                        bW.Write((byte)(0x80 | (4 - i)));
                        bW.Write(bytesValueLength.Slice(i, 4 - i));
                        break;
                    }
                }
            }
        }
    }
}
