/*
Technitium Library
Copyright (C) 2017  Shreyas Zare (shreyas@technitium.com)

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
    public class BinaryNumber : IWriteStream, IEquatable<BinaryNumber>, IComparable<BinaryNumber>
    {
        #region variables

        byte[] _number;

        #endregion

        #region constructor

        public BinaryNumber(byte[] number)
        {
            _number = number;
        }

        public BinaryNumber(Stream s)
        {
            int length = s.ReadByte();
            if (length < 0)
                throw new EndOfStreamException();

            _number = new byte[length];
            OffsetStream.StreamRead(s, _number, 0, length);
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
            byte[] number = new byte[count];
            Buffer.BlockCopy(buffer, offset, number, 0, count);

            return new BinaryNumber(number);
        }

        #endregion

        #region public

        public BinaryNumber Clone()
        {
            byte[] number = new byte[_number.Length];
            Buffer.BlockCopy(_number, 0, number, 0, _number.Length);
            return new BinaryNumber(number);
        }

        public bool Equals(BinaryNumber obj)
        {
            if (ReferenceEquals(null, obj))
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            byte[] objNumber = obj._number;

            if (_number.Length != objNumber.Length)
                return false;

            for (int i = 0; i < _number.Length; i++)
            {
                if (_number[i] != objNumber[i])
                    return false;
            }

            return true;
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as BinaryNumber);
        }

        public override int GetHashCode()
        {
            if (_number.Length < 4)
                return 0;
            else
                return BitConverter.ToInt32(_number, 0);
        }

        public int CompareTo(BinaryNumber other)
        {
            if (this._number.Length != other._number.Length)
                throw new ArgumentException("Operand number length not equal.");

            for (int i = 0; i < this._number.Length; i++)
            {
                if (this._number[i] > other._number[i])
                    return 1;

                if (this._number[i] < other._number[i])
                    return -1;
            }

            return 0;
        }

        public override string ToString()
        {
            return BitConverter.ToString(_number).Replace("-", "").ToLower();
        }

        public void WriteTo(Stream s)
        {
            s.WriteByte(Convert.ToByte(_number.Length));
            s.Write(_number, 0, _number.Length);
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
            if (b1._number.Length != b2._number.Length)
                throw new ArgumentException("Operand number length not equal.");

            byte[] number = new byte[b1._number.Length];

            for (int i = 0; i < number.Length; i++)
                number[i] = (byte)(b1._number[i] | b2._number[i]);

            return new BinaryNumber(number);
        }

        public static BinaryNumber operator &(BinaryNumber b1, BinaryNumber b2)
        {
            if (b1._number.Length != b2._number.Length)
                throw new ArgumentException("Operand number length not equal.");

            byte[] number = new byte[b1._number.Length];

            for (int i = 0; i < number.Length; i++)
                number[i] = (byte)(b1._number[i] & b2._number[i]);

            return new BinaryNumber(number);
        }

        public static BinaryNumber operator ^(BinaryNumber b1, BinaryNumber b2)
        {
            if (b1._number.Length != b2._number.Length)
                throw new ArgumentException("Operand number length not equal.");

            byte[] number = new byte[b1._number.Length];

            for (int i = 0; i < number.Length; i++)
                number[i] = (byte)(b1._number[i] ^ b2._number[i]);

            return new BinaryNumber(number);
        }

        public static BinaryNumber operator >>(BinaryNumber b1, int bitcount)
        {
            byte[] number = new byte[b1._number.Length];

            if (bitcount >= 8)
                Buffer.BlockCopy(b1._number, 0, number, bitcount / 8, number.Length - (bitcount / 8));
            else
                Buffer.BlockCopy(b1._number, 0, number, 0, number.Length);

            bitcount = bitcount % 8;

            if (bitcount > 0)
            {
                for (int i = number.Length - 1; i >= 0; i--)
                {
                    number[i] >>= bitcount;

                    if (i > 0)
                        number[i] |= (byte)(number[i - 1] << (8 - bitcount));
                }
            }

            return new BinaryNumber(number);
        }

        public static BinaryNumber operator <<(BinaryNumber b1, int bitcount)
        {
            byte[] number = new byte[b1._number.Length];

            if (bitcount >= 8)
                Buffer.BlockCopy(b1._number, bitcount / 8, number, 0, number.Length - (bitcount / 8));
            else
                Buffer.BlockCopy(b1._number, 0, number, 0, number.Length);

            bitcount = bitcount % 8;

            if (bitcount > 0)
            {
                for (int i = 0; i < number.Length; i++)
                {
                    number[i] <<= bitcount;

                    if (i < (number.Length - 1))
                        number[i] |= (byte)(number[i + 1] >> (8 - bitcount));
                }
            }

            return new BinaryNumber(number);
        }

        public static bool operator <(BinaryNumber b1, BinaryNumber b2)
        {
            if (b1._number.Length != b2._number.Length)
                throw new ArgumentException("Operand number length not equal.");

            bool eq = true;

            for (int i = 0; i < b1._number.Length; i++)
            {
                if (b1._number[i] > b2._number[i])
                    return false;

                if (b1._number[i] != b2._number[i])
                    eq = false;
            }

            if (eq)
                return false;

            return true;
        }

        public static bool operator >(BinaryNumber b1, BinaryNumber b2)
        {
            if (b1._number.Length != b2._number.Length)
                throw new ArgumentException("Operand number length not equal.");

            bool eq = true;

            for (int i = 0; i < b1._number.Length; i++)
            {
                if (b1._number[i] < b2._number[i])
                    return false;

                if (b1._number[i] != b2._number[i])
                    eq = false;
            }

            if (eq)
                return false;

            return true;
        }

        public static bool operator <=(BinaryNumber b1, BinaryNumber b2)
        {
            if (b1._number.Length != b2._number.Length)
                throw new ArgumentException("Operand number length not equal.");

            for (int i = 0; i < b1._number.Length; i++)
            {
                if (b1._number[i] > b2._number[i])
                    return false;
            }

            return true;
        }

        public static bool operator >=(BinaryNumber b1, BinaryNumber b2)
        {
            if (b1._number.Length != b2._number.Length)
                throw new ArgumentException("Operand number length not equal.");

            for (int i = 0; i < b1._number.Length; i++)
            {
                if (b1._number[i] < b2._number[i])
                    return false;
            }

            return true;
        }

        public static BinaryNumber operator ~(BinaryNumber b1)
        {
            BinaryNumber obj = b1.Clone();

            for (int i = 0; i < obj._number.Length; i++)
            {
                obj._number[i] = (byte)~obj._number[i];
            }

            return obj;
        }

        #endregion

        #region properties

        public byte[] Number
        { get { return _number; } }

        #endregion
    }
}
