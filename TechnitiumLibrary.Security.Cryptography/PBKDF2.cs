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
using System.Security.Cryptography;
using System.Text;

namespace TechnitiumLibrary.Security.Cryptography
{
    //reference: https://www.ietf.org/rfc/rfc2898.txt

    public class PBKDF2 : DeriveBytes
    {
        #region variables

        static readonly RandomNumberGenerator _rng = new RNGCryptoServiceProvider();

        HMAC _PRF;
        byte[] _password;
        byte[] _salt;
        int _iterationCount;

        #endregion

        #region constructor

        public PBKDF2(HMAC PRF, byte[] password, byte[] salt, int iterationCount)
        {
            _PRF = PRF;
            _password = password;
            _salt = salt;
            _iterationCount = iterationCount;
        }

        #endregion

        #region static

        public static PBKDF2 CreateHMACSHA1(string password, byte[] salt, int iterationCount)
        {
            return CreateHMACSHA1(Encoding.UTF8.GetBytes(password), salt, iterationCount);
        }

        public static PBKDF2 CreateHMACSHA1(byte[] password, byte[] salt, int iterationCount)
        {
            return new PBKDF2(new HMACSHA256(password), password, salt, iterationCount);
        }

        public static PBKDF2 CreateHMACSHA1(string password, int saltLength, int iterationCount)
        {
            return CreateHMACSHA1(Encoding.UTF8.GetBytes(password), saltLength, iterationCount);
        }

        public static PBKDF2 CreateHMACSHA1(byte[] password, int saltLength, int iterationCount)
        {
            HMAC PRF = new HMACSHA1(password);

            byte[] salt = new byte[saltLength];
            _rng.GetBytes(salt);

            return new PBKDF2(PRF, password, salt, iterationCount);
        }

        public static PBKDF2 CreateHMACSHA256(string password, byte[] salt, int iterationCount)
        {
            return CreateHMACSHA256(Encoding.UTF8.GetBytes(password), salt, iterationCount);
        }

        public static PBKDF2 CreateHMACSHA256(byte[] password, byte[] salt, int iterationCount)
        {
            return new PBKDF2(new HMACSHA256(password), password, salt, iterationCount);
        }

        public static PBKDF2 CreateHMACSHA256(string password, int saltLength, int iterationCount)
        {
            return CreateHMACSHA256(Encoding.UTF8.GetBytes(password), saltLength, iterationCount);
        }

        public static PBKDF2 CreateHMACSHA256(byte[] password, int saltLength, int iterationCount)
        {
            HMAC PRF = new HMACSHA256(password);

            byte[] salt = new byte[saltLength];
            _rng.GetBytes(salt);

            return new PBKDF2(PRF, password, salt, iterationCount);
        }

        #endregion

        #region IDisposable

        private bool _disposed = false;

        protected override void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_PRF != null)
                    _PRF.Dispose();
            }

            _disposed = true;

            base.Dispose(disposing);
        }

        #endregion

        #region private

        private byte[] F(int i)
        {
            // F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
            //    where

            //          U_1 = PRF (P, S || INT (i)) ,
            //          U_2 = PRF (P, U_1) ,
            //          ...
            //          U_c = PRF (P, U_{c-1}) .

            //Here, INT (i) is a four-octet encoding of the integer i, most
            //significant octet first.

            byte[] outputBuffer = null;
            byte[] U_x = new byte[_salt.Length + 4];

            //INT (i)
            byte[] bINT = BitConverter.GetBytes(i);
            Array.Reverse(bINT); //convert to big-endian or network byte order

            //S || INT (i)
            Buffer.BlockCopy(_salt, 0, U_x, 0, _salt.Length);
            Buffer.BlockCopy(bINT, 0, U_x, _salt.Length, 4);

            for (int U_i = 0; U_i < _iterationCount; U_i++)
            {
                U_x = _PRF.ComputeHash(U_x);

                if (outputBuffer == null)
                {
                    outputBuffer = U_x;
                }
                else
                {
                    for (int j = 0; j < outputBuffer.Length; j++)
                        outputBuffer[j] ^= U_x[j];
                }
            }

            return outputBuffer;
        }

        #endregion

        #region overrides

        public override byte[] GetBytes(int dkLen)
        {
            int hLen = _PRF.HashSize / 8;
            int l = Convert.ToInt32(Math.Ceiling(dkLen / Convert.ToDouble(hLen)));
            byte[] T_x = new byte[l * hLen];

            //T_1 = F (P, S, c, 1) ,
            //T_2 = F (P, S, c, 2) ,
            //...
            //T_l = F (P, S, c, l)
            //
            //DK = T_1 || T_2 ||  ...  || T_l<0..r-1>

            for (int i = 0; i < l; i++)
            {
                byte[] T_i = F(i + 1);
                Buffer.BlockCopy(T_i, 0, T_x, i * hLen, hLen);
            }

            byte[] DK = new byte[dkLen];

            //copy needed bytes to output
            Buffer.BlockCopy(T_x, 0, DK, 0, dkLen);

            return DK;
        }

        public override void Reset()
        {
            //nothing to reset
        }

        #endregion

        #region properties

        public int IterationCount
        { get { return _iterationCount; } }

        public byte[] Salt
        { get { return _salt; } }

        #endregion
    }
}
