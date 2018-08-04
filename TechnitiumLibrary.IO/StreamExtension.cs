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

using System.IO;

namespace TechnitiumLibrary.IO
{
    public static class StreamExtension
    {
        public static void ReadBytes(this Stream s, byte[] buffer, int offset, int count)
        {
            int bytesRead;

            while (count > 0)
            {
                bytesRead = s.Read(buffer, offset, count);

                if (bytesRead < 1)
                    throw new EndOfStreamException();

                offset += bytesRead;
                count -= bytesRead;
            }
        }

        public static byte[] ReadBytes(this Stream s, int count)
        {
            byte[] buffer = new byte[count];
            ReadBytes(s, buffer, 0, count);

            return buffer;
        }

        public static void Write(this Stream s, byte[] buffer)
        {
            s.Write(buffer, 0, buffer.Length);
        }

        public static void CopyTo(this Stream s, Stream destination, int bufferSize, int length)
        {
            if (length < 1)
                return;

            if (length < bufferSize)
                bufferSize = length;

            byte[] buffer = new byte[bufferSize];
            int bytesRead;

            while (length > 0)
            {
                if (length < bufferSize)
                    bufferSize = length;

                bytesRead = s.Read(buffer, 0, bufferSize);
                if (bytesRead < 1)
                    throw new EndOfStreamException();

                destination.Write(buffer, 0, bytesRead);
                length -= bytesRead;
            }
        }
    }
}
