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
using System.Security.Cryptography;

namespace TechnitiumLibrary.IO
{
    public class BinaryNumber : IEquatable<BinaryNumber>, IComparable<BinaryNumber>
    {
        #region variables

        byte[] _value;

        #endregion

        #region constructor

        public BinaryNumber(byte[] value)
        {
            _value = value;
        }

        public BinaryNumber(Stream s)
        {
            int length = s.ReadByte();
            if (length < 0)
                throw new EndOfStreamException();

            _value = new byte[length];
            s.ReadBytes(_value, 0, length);
        }

        #endregion

        #region static

        static RandomNumberGenerator _rnd = new RNGCryptoServiceProvider();

        public static BinaryNumber GenerateRandomNumber160()
        {
            byte[] buffer = new byte[20];

            _rnd.GetBytes(buffer);

            return new BinaryNumber(buffer);
        }

        public static BinaryNumber GenerateRandomNumber256()
        {
            byte[] buffer = new byte[32];

            _rnd.GetBytes(buffer);

            return new BinaryNumber(buffer);
        }

        public static BinaryNumber MaxValueNumber160()
        {
            return new BinaryNumber(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
        }

        public static BinaryNumber Clone(byte[] buffer, int offset, int count)
        {
            byte[] value = new byte[count];
            Buffer.BlockCopy(buffer, offset, value, 0, count);

            return new BinaryNumber(value);
        }

        public static bool Equals(byte[] value1, byte[] value2)
        {
            if ((value1 == null) && (value2 == null))
                return true;

            if ((value1 == null) || (value2 == null))
                return false;

            if (ReferenceEquals(value1, value2))
                return true;

            if (value1.Length != value2.Length)
                return false;

            for (int i = 0; i < value1.Length; i++)
            {
                if (value1[i] != value2[i])
                    return false;
            }

            return true;
        }

        public static BinaryNumber Parse(string value)
        {
            if ((value.Length & 1) == 1)
                throw new ArgumentException("Value length must be a multiple of 2.");

            int len = value.Length;
            byte[] output = new byte[len / 2];

            for (int i = 0; i < len; i += 2)
                output[i / 2] = Convert.ToByte(value.Substring(i, 2), 16);

            return new BinaryNumber(output);
        }

        #endregion

        #region public

        public BinaryNumber Clone()
        {
            byte[] value = new byte[_value.Length];
            Buffer.BlockCopy(_value, 0, value, 0, _value.Length);
            return new BinaryNumber(value);
        }

        public bool Equals(BinaryNumber obj)
        {
            if (obj is null)
                return false;

            return Equals(_value, obj._value);
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as BinaryNumber);
        }

        public override int GetHashCode()
        {
            if (_value.Length < 4)
                return 0;
            else
                return BitConverter.ToInt32(_value, 0);
        }

        public int CompareTo(BinaryNumber other)
        {
            if (this._value.Length != other._value.Length)
                throw new ArgumentException("Operand value length not equal.");

            for (int i = 0; i < this._value.Length; i++)
            {
                if (this._value[i] > other._value[i])
                    return 1;

                if (this._value[i] < other._value[i])
                    return -1;
            }

            return 0;
        }

        public override string ToString()
        {
            return BitConverter.ToString(_value).Replace("-", "").ToLower();
        }

        public void WriteTo(Stream s)
        {
            s.WriteByte(Convert.ToByte(_value.Length));
            s.Write(_value, 0, _value.Length);
        }

        #endregion

        #region operators

        public static bool operator ==(BinaryNumber b1, BinaryNumber b2)
        {
            if (ReferenceEquals(b1, b2))
                return true;

            return b1.Equals(b2);
        }

        public static bool operator !=(BinaryNumber b1, BinaryNumber b2)
        {
            if (ReferenceEquals(b1, b2))
                return false;

            return !b1.Equals(b2);
        }

        public static BinaryNumber operator |(BinaryNumber b1, BinaryNumber b2)
        {
            if (b1._value.Length != b2._value.Length)
                throw new ArgumentException("Operand value length not equal.");

            byte[] value = new byte[b1._value.Length];

            for (int i = 0; i < value.Length; i++)
                value[i] = (byte)(b1._value[i] | b2._value[i]);

            return new BinaryNumber(value);
        }

        public static BinaryNumber operator &(BinaryNumber b1, BinaryNumber b2)
        {
            if (b1._value.Length != b2._value.Length)
                throw new ArgumentException("Operand value length not equal.");

            byte[] value = new byte[b1._value.Length];

            for (int i = 0; i < value.Length; i++)
                value[i] = (byte)(b1._value[i] & b2._value[i]);

            return new BinaryNumber(value);
        }

        public static BinaryNumber operator ^(BinaryNumber b1, BinaryNumber b2)
        {
            if (b1._value.Length != b2._value.Length)
                throw new ArgumentException("Operand value length not equal.");

            byte[] value = new byte[b1._value.Length];

            for (int i = 0; i < value.Length; i++)
                value[i] = (byte)(b1._value[i] ^ b2._value[i]);

            return new BinaryNumber(value);
        }

        public static BinaryNumber operator >>(BinaryNumber b1, int bitcount)
        {
            byte[] value = new byte[b1._value.Length];

            if (bitcount >= 8)
                Buffer.BlockCopy(b1._value, 0, value, bitcount / 8, value.Length - (bitcount / 8));
            else
                Buffer.BlockCopy(b1._value, 0, value, 0, value.Length);

            bitcount = bitcount % 8;

            if (bitcount > 0)
            {
                for (int i = value.Length - 1; i >= 0; i--)
                {
                    value[i] >>= bitcount;

                    if (i > 0)
                        value[i] |= (byte)(value[i - 1] << (8 - bitcount));
                }
            }

            return new BinaryNumber(value);
        }

        public static BinaryNumber operator <<(BinaryNumber b1, int bitcount)
        {
            byte[] value = new byte[b1._value.Length];

            if (bitcount >= 8)
                Buffer.BlockCopy(b1._value, bitcount / 8, value, 0, value.Length - (bitcount / 8));
            else
                Buffer.BlockCopy(b1._value, 0, value, 0, value.Length);

            bitcount = bitcount % 8;

            if (bitcount > 0)
            {
                for (int i = 0; i < value.Length; i++)
                {
                    value[i] <<= bitcount;

                    if (i < (value.Length - 1))
                        value[i] |= (byte)(value[i + 1] >> (8 - bitcount));
                }
            }

            return new BinaryNumber(value);
        }

        public static bool operator <(BinaryNumber b1, BinaryNumber b2)
        {
            if (b1._value.Length != b2._value.Length)
                throw new ArgumentException("Operand value length not equal.");

            bool eq = true;

            for (int i = 0; i < b1._value.Length; i++)
            {
                if (b1._value[i] > b2._value[i])
                    return false;

                if (b1._value[i] != b2._value[i])
                    eq = false;
            }

            if (eq)
                return false;

            return true;
        }

        public static bool operator >(BinaryNumber b1, BinaryNumber b2)
        {
            if (b1._value.Length != b2._value.Length)
                throw new ArgumentException("Operand value length not equal.");

            bool eq = true;

            for (int i = 0; i < b1._value.Length; i++)
            {
                if (b1._value[i] < b2._value[i])
                    return false;

                if (b1._value[i] != b2._value[i])
                    eq = false;
            }

            if (eq)
                return false;

            return true;
        }

        public static bool operator <=(BinaryNumber b1, BinaryNumber b2)
        {
            if (b1._value.Length != b2._value.Length)
                throw new ArgumentException("Operand value length not equal.");

            for (int i = 0; i < b1._value.Length; i++)
            {
                if (b1._value[i] > b2._value[i])
                    return false;
            }

            return true;
        }

        public static bool operator >=(BinaryNumber b1, BinaryNumber b2)
        {
            if (b1._value.Length != b2._value.Length)
                throw new ArgumentException("Operand value length not equal.");

            for (int i = 0; i < b1._value.Length; i++)
            {
                if (b1._value[i] < b2._value[i])
                    return false;
            }

            return true;
        }

        public static BinaryNumber operator ~(BinaryNumber b1)
        {
            BinaryNumber obj = b1.Clone();

            for (int i = 0; i < obj._value.Length; i++)
            {
                obj._value[i] = (byte)~obj._value[i];
            }

            return obj;
        }

        #endregion

        #region properties

        public byte[] Value
        { get { return _value; } }

        #endregion
    }
}
