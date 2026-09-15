/*
Technitium Library
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using System;
using System.Security.Cryptography;

namespace TechnitiumLibrary.Net.Dns.Dnssec
{
    public class DnssecMldsaPublicKey : DnssecPublicKey
    {
        #region variables

        const int PUBLIC_KEY_LENGTH = 1312;
        const int SIGNATURE_LENGTH = 2420;

        readonly MLDsaPublicKeyParameters _mldsaPublicKey;

        #endregion

        #region constructors

        public DnssecMldsaPublicKey(byte[] rawPublicKey)
            : base(rawPublicKey)
        {
            if (rawPublicKey.Length != PUBLIC_KEY_LENGTH)
                throw new ArgumentException("An ML-DSA-44 DNSKEY public key must be exactly 1312 bytes.", nameof(rawPublicKey));

            _mldsaPublicKey = MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_44, rawPublicKey);
        }

        #endregion

        #region public

        public override bool IsSignatureValid(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm)
        {
            if (signature.Length != SIGNATURE_LENGTH)
                return false;

            MLDsaSigner verifier = new MLDsaSigner(MLDsaParameters.ml_dsa_44, false);
            verifier.Init(false, _mldsaPublicKey);
            verifier.BlockUpdate(hash, 0, hash.Length);

            return verifier.VerifySignature(signature);
        }

        #endregion

        #region properties

        public override bool IsAlgorithmSupported
        { get { return true; } }

        #endregion
    }
}
