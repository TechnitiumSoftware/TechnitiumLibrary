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
    public class RC4Managed : SymmetricAlgorithm
    {
        #region variables

        static readonly RandomNumberGenerator _rnd = new RNGCryptoServiceProvider();

        #endregion

        #region constructor

        public RC4Managed()
        {
            this.LegalKeySizesValue = new KeySizes[] { new KeySizes(128, 512, 128) };
            this.KeySizeValue = 256;

            GenerateKey();
            GenerateIV();
        }

        public RC4Managed(int keySize)
        {
            this.LegalKeySizesValue = new KeySizes[] { new KeySizes(128, 256, 128) };
            this.KeySize = keySize;

            GenerateKey();
            GenerateIV();
        }

        public RC4Managed(byte[] key, byte[] IV)
        {
            this.LegalKeySizesValue = new KeySizes[] { new KeySizes(128, 512, 128) };
            this.KeySize = key.Length * 8;

            this.KeyValue = key;
            this.IVValue = IV;
        }

        #endregion

        #region overrides

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new RC4Transform(rgbKey, rgbIV);
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new RC4Transform(rgbKey, rgbIV);
        }

        public override void GenerateIV()
        {
            byte[] iv = new byte[this.KeySizeValue / 8];
            _rnd.GetBytes(iv);

            this.IVValue = iv;
        }

        public override void GenerateKey()
        {
            byte[] key = new byte[this.KeySizeValue / 8];
            _rnd.GetBytes(key);

            this.KeyValue = key;
        }

        #endregion

        class RC4Transform : ICryptoTransform
        {
            #region variables

            byte[] s = new byte[256];
            int xi = 0;
            int xj = 0;

            #endregion

            #region constructor

            public RC4Transform(byte[] key, byte[] IV)
            {
                //mix key with IV by taking HMAC
                HMAC hmac = new HMACSHA256(key);
                key = hmac.ComputeHash(IV);

                //RC4 key scheduling algo
                for (int i = 0; i < 256; i++)
                    s[i] = (byte)i;

                int j = 0;
                byte tmp;

                for (int i = 0; i < 256; i++)
                {
                    j = (j + s[i] + key[i % key.Length]) & 0xFF;

                    tmp = s[i];
                    s[i] = s[j];
                    s[j] = tmp;
                }
            }

            #endregion

            #region Dispose

            public void Dispose()
            {
                for (int i = 0; i < 256; i++)
                    s[i] = 0;

                xi = 0;
                xj = 0;
            }

            #endregion

            #region algorithm

            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                byte temp;

                for (int i = 0; i < inputCount; i++)
                {
                    xi = (xi + 1) & 0xFF;
                    xj = (xj + s[xi]) & 0xFF;

                    temp = s[xi];
                    s[xi] = s[xj];
                    s[xj] = temp;

                    outputBuffer[outputOffset + i] = Convert.ToByte(inputBuffer[inputOffset + i] ^ s[(s[xi] + s[xj]) & 0xFF]);
                }

                return inputCount;
            }

            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                return new byte[] { };
            }

            #endregion

            #region properties

            public bool CanReuseTransform
            { get { return false; } }

            public bool CanTransformMultipleBlocks
            { get { return true; } }

            public int InputBlockSize
            { get { return 8; } }

            public int OutputBlockSize
            { get { return 8; } }

            #endregion
        }
    }
}
