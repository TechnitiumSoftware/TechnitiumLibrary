/*
Technitium Library
Copyright (C) 2018  Shreyas Zare (shreyas@technitium.com)

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
using System.IO;
using System.Text;

namespace TechnitiumLibrary.IO
{
    public static class BinaryReaderExtension
    {
        static readonly DateTime _epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static byte[] ReadBuffer(this BinaryReader bR)
        {
            return bR.ReadBytes(ReadLength(bR));
        }

        public static string ReadShortString(this BinaryReader bR)
        {
            return Encoding.UTF8.GetString(bR.ReadBytes(bR.ReadByte()));
        }

        public static DateTime ReadDate(this BinaryReader bR)
        {
            return _epoch.AddMilliseconds(bR.ReadInt64());
        }

        public static int ReadLength(this BinaryReader bR)
        {
            int length1 = bR.ReadByte();
            if (length1 > 127)
            {
                int numberLenBytes = length1 & 0x7F;

                byte[] valueBytes = new byte[4];
                bR.BaseStream.ReadBytes(valueBytes, 0, numberLenBytes);

                switch (numberLenBytes)
                {
                    case 1:
                        return valueBytes[0];

                    case 2:
                        Array.Reverse(valueBytes, 0, 2);
                        return BitConverter.ToInt32(valueBytes, 0);

                    case 3:
                        Array.Reverse(valueBytes, 0, 3);
                        return BitConverter.ToInt32(valueBytes, 0);

                    case 4:
                        Array.Reverse(valueBytes, 0, 4);
                        return BitConverter.ToInt32(valueBytes, 0);

                    default:
                        throw new IOException("BinaryReaderExtension encoding length not supported.");
                }
            }
            else
            {
                return length1;
            }
        }
    }
}
