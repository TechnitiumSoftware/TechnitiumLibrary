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
using System.Runtime.Serialization;
using System.Security.Cryptography;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns.Dnssec
{
    public class DnssecEcdsaPublicKey : DnssecPublicKey
    {
        #region variables

        readonly ECParameters _ecdsaPublicKey;

        #endregion

        #region constructors

        public DnssecEcdsaPublicKey(ECParameters ecdsaPublicKey)
        {
            _ecdsaPublicKey = ecdsaPublicKey;

            if (_ecdsaPublicKey.Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value)
            {
                _rawPublicKey = new byte[64];

                Buffer.BlockCopy(_ecdsaPublicKey.Q.X, 0, _rawPublicKey, 0, 32);
                Buffer.BlockCopy(_ecdsaPublicKey.Q.Y, 0, _rawPublicKey, 32, 32);
            }
            else if (_ecdsaPublicKey.Curve.Oid.Value == ECCurve.NamedCurves.nistP384.Oid.Value)
            {
                _rawPublicKey = new byte[96];

                Buffer.BlockCopy(_ecdsaPublicKey.Q.X, 0, _rawPublicKey, 0, 48);
                Buffer.BlockCopy(_ecdsaPublicKey.Q.Y, 0, _rawPublicKey, 48, 48);
            }
            else
            {
                throw new NotSupportedException("ECDSA algorithm is not supported: " + _ecdsaPublicKey.Curve.Oid.FriendlyName);
            }
        }

        public DnssecEcdsaPublicKey(byte[] rawPublicKey, DnssecAlgorithm algorithm)
            : base(rawPublicKey)
        {
            switch (algorithm)
            {
                case DnssecAlgorithm.ECDSAP256SHA256:
                    {
                        byte[] x = new byte[32];
                        byte[] y = new byte[32];

                        Buffer.BlockCopy(rawPublicKey, 0, x, 0, 32);
                        Buffer.BlockCopy(rawPublicKey, 32, y, 0, 32);

                        _ecdsaPublicKey.Curve = ECCurve.NamedCurves.nistP256;
                        _ecdsaPublicKey.Q = new ECPoint() { X = x, Y = y };
                    }
                    break;

                case DnssecAlgorithm.ECDSAP384SHA384:
                    {
                        byte[] x = new byte[48];
                        byte[] y = new byte[48];

                        Buffer.BlockCopy(rawPublicKey, 0, x, 0, 48);
                        Buffer.BlockCopy(rawPublicKey, 48, y, 0, 48);

                        _ecdsaPublicKey.Curve = ECCurve.NamedCurves.nistP384;
                        _ecdsaPublicKey.Q = new ECPoint() { X = x, Y = y };
                    }
                    break;

                default:
                    throw new NotSupportedException();
            }
        }

        #endregion

        #region public

        public override bool IsSignatureValid(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm)
        {
            using (ECDsa ecdsa = ECDsa.Create(_ecdsaPublicKey))
            {
                return ecdsa.VerifyHash(hash, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
        }

        public override string ToString()
        {
            return Convert.ToBase64String(_ecdsaPublicKey.Q.X) + " " + Convert.ToBase64String(_ecdsaPublicKey.Q.Y);
        }

        #endregion

        #region properties

        public ECParameters EcdsaPublicKey
        { get { return _ecdsaPublicKey; } }

        [IgnoreDataMember]
        public override bool IsAlgorithmSupported
        { get { return true; } }

        #endregion
    }
}
