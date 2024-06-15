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
using System.IO;
using System.Security.Cryptography;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns.Dnssec
{
    public class DnssecPublicKey
    {
        #region variables

        protected byte[] _rawPublicKey;

        #endregion

        #region constructor

        protected DnssecPublicKey()
        { }

        protected DnssecPublicKey(byte[] rawPublicKey)
        {
            _rawPublicKey = rawPublicKey;
        }

        #endregion

        #region static

        public static DnssecPublicKey Parse(DnssecAlgorithm algorithm, byte[] rawPublicKey)
        {
            switch (algorithm)
            {
                case DnssecAlgorithm.RSAMD5:
                case DnssecAlgorithm.RSASHA1:
                case DnssecAlgorithm.RSASHA256:
                case DnssecAlgorithm.RSASHA512:
                case DnssecAlgorithm.RSASHA1_NSEC3_SHA1:
                    return new DnssecRsaPublicKey(rawPublicKey);

                case DnssecAlgorithm.ECDSAP256SHA256:
                case DnssecAlgorithm.ECDSAP384SHA384:
                    return new DnssecEcdsaPublicKey(rawPublicKey, algorithm);

                default:
                    return new DnssecPublicKey(rawPublicKey);
            }
        }

        #endregion

        #region public

        public virtual bool IsSignatureValid(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm)
        {
            throw new NotSupportedException("DNSSEC algorithm is not supported.");
        }

        public void WriteTo(Stream s)
        {
            s.Write(_rawPublicKey);
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnssecPublicKey other)
                return BinaryNumber.Equals(_rawPublicKey, other._rawPublicKey);

            return false;
        }

        public override int GetHashCode()
        {
            return _rawPublicKey.GetArrayHashCode();
        }

        public override string ToString()
        {
            return Convert.ToBase64String(_rawPublicKey);
        }

        #endregion

        #region properties

        public byte[] RawPublicKey
        { get { return _rawPublicKey; } }

        public virtual bool IsAlgorithmSupported
        { get { return false; } }

        #endregion
    }
}
