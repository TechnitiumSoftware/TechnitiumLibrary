/*
Technitium Library
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace TechnitiumLibrary.Security.OTP
{
    //HOTP: An HMAC-Based One-Time Password Algorithm
    //https://datatracker.ietf.org/doc/rfc4226/

    //TOTP: Time-Based One-Time Password Algorithm 
    //https://datatracker.ietf.org/doc/rfc6238/

    public class Authenticator
    {
        #region variables

        readonly AuthenticatorKeyUri _keyUri;
        readonly byte[] _key;

        #endregion

        #region constructor

        public Authenticator(AuthenticatorKeyUri keyUri)
        {
            if (!keyUri.Type.Equals("totp", StringComparison.OrdinalIgnoreCase))
                throw new NotSupportedException($"The authenticator key URI type '{_keyUri.Type}' is not supported.");

            _keyUri = keyUri;
            _key = Base32.FromBase32String(_keyUri.Secret);
        }

        #endregion

        #region private

        private static string HOTP(byte[] k, long c, int digits = 6, string algorithm = "SHA1")
        {
            HMAC hmac = null;
            try
            {
                int outLength;

                switch (algorithm.ToUpperInvariant())
                {
                    case "SHA1":
                        hmac = new HMACSHA1(k);
                        outLength = SHA1.HashSizeInBytes;
                        break;

                    case "SHA256":
                        hmac = new HMACSHA256(k);
                        outLength = SHA256.HashSizeInBytes;
                        break;

                    case "SHA512":
                        hmac = new HMACSHA512(k);
                        outLength = SHA512.HashSizeInBytes;
                        break;

                    default:
                        throw new NotSupportedException("Hash algorithm is not supported: " + algorithm);
                }

                Span<byte> bc = stackalloc byte[8];
                BinaryPrimitives.WriteInt64BigEndian(bc, c);

                Span<byte> hs = stackalloc byte[outLength];

                if (!hmac.TryComputeHash(bc, hs, out _))
                    throw new InvalidOperationException();

                int offset = hs[hs.Length - 1] & 0xf;
                int code = (hs[offset] & 0x7f) << 24 | hs[offset + 1] << 16 | hs[offset + 2] << 8 | hs[offset + 3];

                return (code % (int)Math.Pow(10, digits)).ToString().PadLeft(digits, '0');
            }
            finally
            {
                hmac?.Dispose();
            }
        }

        private static string TOTP(byte[] k, DateTime dateTime, int t0 = 0, int period = 30, int digits = 6, string algorithm = "SHA1")
        {
            long t = (long)Math.Floor(((dateTime - DateTime.UnixEpoch).TotalSeconds - t0) / period);

            return HOTP(k, t, digits, algorithm);
        }

        #endregion

        #region public

        public string GetTOTP()
        {
            return GetTOTP(DateTime.UtcNow);
        }

        public string GetTOTP(DateTime dateTime)
        {
            return TOTP(_key, dateTime, 0, _keyUri.Period, _keyUri.Digits, _keyUri.Algorithm);
        }

        public bool IsTOTPValid(string totp, byte fudge = 10)
        {
            DateTime utcNow = DateTime.UtcNow;

            if (GetTOTP(utcNow).Equals(totp))
                return true;

            int period = _keyUri.Period;
            int seconds;

            for (int i = 1; i <= fudge; i++)
            {
                seconds = i * period;

                if (GetTOTP(utcNow.AddSeconds(seconds)).Equals(totp))
                    return true;

                if (GetTOTP(utcNow.AddSeconds(-seconds)).Equals(totp))
                    return true;
            }

            return false;
        }

        #endregion

        #region properties

        public AuthenticatorKeyUri KeyUri
        { get { return _keyUri; } }

        #endregion
    }
}
