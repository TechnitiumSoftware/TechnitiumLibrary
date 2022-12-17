/*
Technitium Library
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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
using System.Text.Json.Serialization;

namespace TechnitiumLibrary.Net.Dns.Dnssec
{
    public class DnssecRsaPublicKey : DnssecPublicKey
    {
        #region variables

        readonly RSAParameters _rsaPublicKey;

        #endregion

        #region constructors

        public DnssecRsaPublicKey(RSAParameters rsaPublicKey)
        {
            _rsaPublicKey = rsaPublicKey;

            if (_rsaPublicKey.Exponent.Length < 256)
            {
                _rawPublicKey = new byte[1 + _rsaPublicKey.Exponent.Length + _rsaPublicKey.Modulus.Length];
                _rawPublicKey[0] = (byte)_rsaPublicKey.Exponent.Length;
                Buffer.BlockCopy(_rsaPublicKey.Exponent, 0, _rawPublicKey, 1, _rsaPublicKey.Exponent.Length);
                Buffer.BlockCopy(_rsaPublicKey.Modulus, 0, _rawPublicKey, 1 + _rsaPublicKey.Exponent.Length, _rsaPublicKey.Modulus.Length);
            }
            else
            {
                byte[] bufferExponentLength = BitConverter.GetBytes(Convert.ToUInt16(_rsaPublicKey.Exponent.Length));
                Array.Reverse(bufferExponentLength);

                _rawPublicKey = new byte[3 + _rsaPublicKey.Exponent.Length + _rsaPublicKey.Modulus.Length];
                Buffer.BlockCopy(bufferExponentLength, 0, _rawPublicKey, 1, 2);
                Buffer.BlockCopy(_rsaPublicKey.Exponent, 0, _rawPublicKey, 3, _rsaPublicKey.Exponent.Length);
                Buffer.BlockCopy(_rsaPublicKey.Modulus, 0, _rawPublicKey, 3 + _rsaPublicKey.Exponent.Length, _rsaPublicKey.Modulus.Length);
            }
        }

        public DnssecRsaPublicKey(byte[] rawPublicKey)
            : base(rawPublicKey)
        {
            if (_rawPublicKey[0] == 0)
            {
                byte[] bufferExponentLength = new byte[2];
                Buffer.BlockCopy(_rawPublicKey, 1, bufferExponentLength, 0, 2);
                Array.Reverse(bufferExponentLength);

                int exponentLength = BitConverter.ToUInt16(bufferExponentLength, 0);
                int modulusLength = _rawPublicKey.Length - exponentLength - 3;

                _rsaPublicKey.Exponent = new byte[exponentLength];
                _rsaPublicKey.Modulus = new byte[modulusLength];

                Buffer.BlockCopy(_rawPublicKey, 3, _rsaPublicKey.Exponent, 0, exponentLength);
                Buffer.BlockCopy(_rawPublicKey, 3 + exponentLength, _rsaPublicKey.Modulus, 0, modulusLength);
            }
            else
            {
                int exponentLength = _rawPublicKey[0];
                int modulusLength = _rawPublicKey.Length - exponentLength - 1;

                _rsaPublicKey.Exponent = new byte[exponentLength];
                _rsaPublicKey.Modulus = new byte[modulusLength];

                Buffer.BlockCopy(_rawPublicKey, 1, _rsaPublicKey.Exponent, 0, exponentLength);
                Buffer.BlockCopy(_rawPublicKey, 1 + exponentLength, _rsaPublicKey.Modulus, 0, modulusLength);
            }
        }

        #endregion

        #region public

        public override bool IsSignatureValid(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm)
        {
            using (RSA rsa = RSA.Create(_rsaPublicKey))
            {
                return rsa.VerifyHash(hash, signature, hashAlgorithm, RSASignaturePadding.Pkcs1);
            }
        }

        #endregion

        #region properties

        public RSAParameters RsaPublicKey
        { get { return _rsaPublicKey; } }

        [JsonIgnore]
        public override bool IsAlgorithmSupported
        { get { return true; } }

        #endregion
    }
}
