/*
Technitium Library
Copyright (C) 2015  Shreyas Zare (shreyas@technitium.com)

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
using System.Security.Cryptography;

namespace TechnitiumLibrary.Security.Cryptography
{
    public class CRC32Managed : HashAlgorithm
    {
        #region variables

        uint[] _crc32Table = new uint[256];

        uint _crc32;
        uint _polynomial;
        uint _preCondition;

        #endregion

        #region contructor

        public CRC32Managed(uint polynomial = 0xEDB88320U, uint preCondition = 0xFFFFFFFFU)
        {
            _polynomial = polynomial;
            _preCondition = preCondition;
            _crc32 = preCondition;

            this.HashSizeValue = 32; //bits

            uint value;

            for (uint iByte = 0; iByte < 256; iByte++)
            {
                value = iByte;

                for (int iBit = 0; iBit < 8; iBit++)
                {
                    if ((value & 1) == 1)
                        value = (value >> 1) ^ _polynomial;
                    else
                        value >>= 1;
                }

                _crc32Table[iByte] = value;
            }
        }

        #endregion

        #region CRC32 Algorithm

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            for (int iByte = ibStart; iByte < (ibStart + cbSize); iByte++)
            {
                _crc32 = (_crc32 >> 8) ^ _crc32Table[(_crc32 & 0xFFU) ^ array[iByte]];
            }
        }

        protected override byte[] HashFinal()
        {
            byte[] output = BitConverter.GetBytes(_crc32 ^ 0xFFFFFFFFU);
            Array.Reverse(output);

            return output;
        }

        public override void Initialize()
        {
            _crc32 = _preCondition;
        }

        #endregion
    }
}
