/*
Technitium Library
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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
using System.Text;

namespace TechnitiumLibrary
{
    //https://www.rfc-editor.org/rfc/rfc4648

    public static class Base32
    {
        #region variables

        readonly static char[] BASE32_MAP = new char[] { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7' };
        readonly static int[] REVERSE_BASE32_MAP;

        readonly static char[] BASE32_HEX_MAP = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V' };
        readonly static int[] REVERSE_BASE32_HEX_MAP;

        #endregion

        #region constructor

        static Base32()
        {
            {
                REVERSE_BASE32_MAP = new int[255];

                for (int i = 0; i < BASE32_MAP.Length; i++)
                    REVERSE_BASE32_MAP[BASE32_MAP[i]] = i;
            }

            {
                REVERSE_BASE32_HEX_MAP = new int[255];

                for (int i = 0; i < BASE32_HEX_MAP.Length; i++)
                    REVERSE_BASE32_HEX_MAP[BASE32_HEX_MAP[i]] = i;
            }
        }

        #endregion

        #region private

        private static string Encode(byte[] data, char[] map, bool skipPadding)
        {
            StringBuilder sb = new StringBuilder();

            int r = data.Length % 5;
            int l = data.Length - r;

            int a, b, c, d, e;

            for (int i = 0; i < l; i += 5)
            {
                a = data[i];
                b = data[i + 1];
                c = data[i + 2];
                d = data[i + 3];
                e = data[i + 4];

                sb.Append(map[a >> 3]);
                sb.Append(map[((a & 0x7) << 2) | (b >> 6)]);
                sb.Append(map[(b & 0x3E) >> 1]);
                sb.Append(map[((b & 0x1) << 4) | ((c & 0xF0) >> 4)]);
                sb.Append(map[((c & 0x0F) << 1) | ((d & 0x80) >> 7)]);
                sb.Append(map[(d & 0x7C) >> 2]);
                sb.Append(map[((d & 0x3) << 3) | ((e & 0xE0) >> 5)]);
                sb.Append(map[e & 0x1F]);
            }

            switch (r)
            {
                case 1:
                    a = data[l];

                    sb.Append(map[a >> 3]);
                    sb.Append(map[(a & 0x7) << 2]);

                    if (!skipPadding)
                        sb.Append("======");

                    break;

                case 2:
                    a = data[l];
                    b = data[l + 1];

                    sb.Append(map[a >> 3]);
                    sb.Append(map[((a & 0x7) << 2) | (b >> 6)]);
                    sb.Append(map[(b & 0x3E) >> 1]);
                    sb.Append(map[(b & 0x1) << 4]);

                    if (!skipPadding)
                        sb.Append("====");

                    break;

                case 3:
                    a = data[l];
                    b = data[l + 1];
                    c = data[l + 2];

                    sb.Append(map[a >> 3]);
                    sb.Append(map[((a & 0x7) << 2) | (b >> 6)]);
                    sb.Append(map[(b & 0x3E) >> 1]);
                    sb.Append(map[((b & 0x1) << 4) | ((c & 0xF0) >> 4)]);
                    sb.Append(map[(c & 0x0F) << 1]);

                    if (!skipPadding)
                        sb.Append("===");

                    break;

                case 4:
                    a = data[l];
                    b = data[l + 1];
                    c = data[l + 2];
                    d = data[l + 3];

                    sb.Append(map[a >> 3]);
                    sb.Append(map[((a & 0x7) << 2) | (b >> 6)]);
                    sb.Append(map[(b & 0x3E) >> 1]);
                    sb.Append(map[((b & 0x1) << 4) | ((c & 0xF0) >> 4)]);
                    sb.Append(map[((c & 0x0F) << 1) | ((d & 0x80) >> 7)]);
                    sb.Append(map[(d & 0x7C) >> 2]);
                    sb.Append(map[(d & 0x3) << 3]);

                    if (!skipPadding)
                        sb.Append('=');

                    break;
            }

            return sb.ToString();
        }

        private static byte[] Decode(string data, int[] rmap)
        {
            byte[] buffer;
            int paddingCount = 0;

            if (data.Length > 0)
            {
                while (data[data.Length - 1 - paddingCount] == '=')
                    paddingCount++;
            }

            switch (paddingCount)
            {
                case 0:
                    buffer = new byte[(data.Length * 5 / 8)];
                    break;

                case 1:
                    buffer = new byte[(data.Length * 5 / 8) - 1];
                    break;

                case 3:
                    buffer = new byte[(data.Length * 5 / 8) - 2];
                    break;

                case 4:
                    buffer = new byte[(data.Length * 5 / 8) - 3];
                    break;

                case 6:
                    buffer = new byte[(data.Length * 5 / 8) - 4];
                    break;

                default:
                    throw new ArgumentException("The string is not a valid base32 string or has invalid padding.", nameof(data));
            }

            int r = (data.Length - paddingCount) % 8;
            int l = data.Length - paddingCount - r;
            int a, b, c, d, e, f, g, h;
            int x = 0;

            for (int i = 0; i < l; i += 8)
            {
                a = rmap[data[i]];
                b = rmap[data[i + 1]];
                c = rmap[data[i + 2]];
                d = rmap[data[i + 3]];
                e = rmap[data[i + 4]];
                f = rmap[data[i + 5]];
                g = rmap[data[i + 6]];
                h = rmap[data[i + 7]];

                buffer[x++] = (byte)((a << 3) | (b >> 2));
                buffer[x++] = (byte)(((b & 0x3) << 6) | (c << 1) | (d >> 4));
                buffer[x++] = (byte)(((d & 0xF) << 4) | (e >> 1));
                buffer[x++] = (byte)(((e & 0x1) << 7) | (f << 2) | (g >> 3));
                buffer[x++] = (byte)(((g & 0x7) << 5) | h);
            }

            switch (r)
            {
                case 1:
                    a = rmap[data[l]];

                    buffer[x++] = (byte)(a << 3);
                    break;

                case 2:
                    a = rmap[data[l]];
                    b = rmap[data[l + 1]];

                    buffer[x++] = (byte)((a << 3) | (b >> 2));
                    break;

                case 3:
                    a = rmap[data[l]];
                    b = rmap[data[l + 1]];
                    c = rmap[data[l + 2]];

                    buffer[x++] = (byte)((a << 3) | (b >> 2));
                    buffer[x++] = (byte)(((b & 0x3) << 6) | (c << 1));
                    break;

                case 4:
                    a = rmap[data[l]];
                    b = rmap[data[l + 1]];
                    c = rmap[data[l + 2]];
                    d = rmap[data[l + 3]];

                    buffer[x++] = (byte)((a << 3) | (b >> 2));
                    buffer[x++] = (byte)(((b & 0x3) << 6) | (c << 1) | (d >> 4));
                    break;

                case 5:
                    a = rmap[data[l]];
                    b = rmap[data[l + 1]];
                    c = rmap[data[l + 2]];
                    d = rmap[data[l + 3]];
                    e = rmap[data[l + 4]];

                    buffer[x++] = (byte)((a << 3) | (b >> 2));
                    buffer[x++] = (byte)(((b & 0x3) << 6) | (c << 1) | (d >> 4));
                    buffer[x++] = (byte)(((d & 0xF) << 4) | (e >> 1));
                    break;

                case 6:
                    a = rmap[data[l]];
                    b = rmap[data[l + 1]];
                    c = rmap[data[l + 2]];
                    d = rmap[data[l + 3]];
                    e = rmap[data[l + 4]];
                    f = rmap[data[l + 5]];

                    buffer[x++] = (byte)((a << 3) | (b >> 2));
                    buffer[x++] = (byte)(((b & 0x3) << 6) | (c << 1) | (d >> 4));
                    buffer[x++] = (byte)(((d & 0xF) << 4) | (e >> 1));
                    buffer[x++] = (byte)(((e & 0x1) << 7) | (f << 2));
                    break;

                case 7:
                    a = rmap[data[l]];
                    b = rmap[data[l + 1]];
                    c = rmap[data[l + 2]];
                    d = rmap[data[l + 3]];
                    e = rmap[data[l + 4]];
                    f = rmap[data[l + 5]];
                    g = rmap[data[l + 6]];

                    buffer[x++] = (byte)((a << 3) | (b >> 2));
                    buffer[x++] = (byte)(((b & 0x3) << 6) | (c << 1) | (d >> 4));
                    buffer[x++] = (byte)(((d & 0xF) << 4) | (e >> 1));
                    buffer[x++] = (byte)(((e & 0x1) << 7) | (f << 2) | (g >> 3));
                    break;
            }

            return buffer;
        }

        #endregion

        #region public

        public static string ToBase32String(byte[] data, bool skipPadding = false)
        {
            return Encode(data, BASE32_MAP, skipPadding);
        }

        public static string ToBase32HexString(byte[] data, bool skipPadding = false)
        {
            return Encode(data, BASE32_HEX_MAP, skipPadding);
        }

        public static byte[] FromBase32String(string data)
        {
            return Decode(data, REVERSE_BASE32_MAP);
        }

        public static byte[] FromBase32HexString(string data)
        {
            return Decode(data, REVERSE_BASE32_HEX_MAP);
        }

        #endregion
    }
}
