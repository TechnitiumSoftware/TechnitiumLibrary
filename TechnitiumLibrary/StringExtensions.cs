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
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace TechnitiumLibrary
{
    public static class StringExtensions
    {
        public static T[] Split<T>(this string value, Func<string, T> parse, params char[] separator)
        {
            string[] parts = value.Split(separator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            T[] array = new T[parts.Length];

            for (int i = 0; i < parts.Length; i++)
                array[i] = parse(parts[i]);

            return array;
        }

        public static string Join<T>(this ICollection<T> values, char separator = ',')
        {
            string strValue = null;

            foreach (T value in values)
            {
                if (strValue is null)
                    strValue = value.ToString();
                else
                    strValue += separator + " " + value.ToString();
            }

            return strValue;
        }

        public static string Join<T>(this IReadOnlyCollection<T> values, char separator = ',')
        {
            string strValue = null;

            foreach (T value in values)
            {
                if (strValue is null)
                    strValue = value.ToString();
                else
                    strValue += separator + " " + value.ToString();
            }

            return strValue;
        }

        public static byte[] ParseColonHexString(this string value)
        {
            int i;
            int j = -1;
            string strHex;
            int b;

            using (MemoryStream mS = new MemoryStream())
            {
                while (true)
                {
                    i = value.IndexOf(':', j + 1);
                    if (i < 0)
                        i = value.Length;

                    strHex = value.Substring(j + 1, i - j - 1);

                    if (!int.TryParse(strHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out b) || (b < byte.MinValue) || (b > byte.MaxValue))
                        throw new ArgumentException("The input string data must be a colon (:) separated hex string.");

                    mS.WriteByte((byte)b);

                    if (i == value.Length)
                        break;

                    j = i;
                }

                return mS.ToArray();
            }
        }
    }
}
