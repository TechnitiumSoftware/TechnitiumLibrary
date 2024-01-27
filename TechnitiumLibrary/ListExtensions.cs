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
using System.Security.Cryptography;

namespace TechnitiumLibrary
{
    public static class ListExtensions
    {
        public static void Shuffle<T>(this IList<T> array)
        {
            Span<byte> buffer = stackalloc byte[4];

            int n = array.Count;
            while (n > 1)
            {
                RandomNumberGenerator.Fill(buffer);
                int k = (BitConverter.ToInt32(buffer) & 0x7FFFFFFF) % n--;
                T temp = array[n];
                array[n] = array[k];
                array[k] = temp;
            }
        }

        public static IList<T2> Convert<T1, T2>(this IList<T1> array, Func<T1, T2> convert)
        {
            T2[] newArray = new T2[array.Count];

            for (int i = 0; i < array.Count; i++)
                newArray[i] = convert(array[i]);

            return newArray;
        }

        public static IReadOnlyList<T2> Convert<T1, T2>(this IReadOnlyList<T1> array, Func<T1, T2> convert)
        {
            T2[] newArray = new T2[array.Count];

            for (int i = 0; i < array.Count; i++)
                newArray[i] = convert(array[i]);

            return newArray;
        }

        public static bool Equals<T>(this IReadOnlyList<T> value1, IReadOnlyList<T> value2)
        {
            if (ReferenceEquals(value1, value2))
                return true;

            if ((value1 is null) || (value2 is null))
                return false;

            if (value1.Count != value2.Count)
                return false;

            for (int i = 0; i < value1.Count; i++)
            {
                if (!value1[i].Equals(value2[i]))
                    return false;
            }

            return true;
        }
    }
}
