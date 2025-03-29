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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using System;
using System.Security.Cryptography;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns.Dnssec
{
    public class DnssecEddsaPublicKey : DnssecPublicKey
    {
        #region variables

        readonly DnssecAlgorithm _algorithm;
        readonly Ed25519PublicKeyParameters _ed25519PublicKey;
        readonly Ed448PublicKeyParameters _ed448PublicKey;

        #endregion

        #region constructors

        public DnssecEddsaPublicKey(Ed25519PublicKeyParameters ed25519PublicKey)
        {
            _algorithm = DnssecAlgorithm.ED25519;
            _ed25519PublicKey = ed25519PublicKey;

            _rawPublicKey = _ed25519PublicKey.GetEncoded();
        }

        public DnssecEddsaPublicKey(Ed448PublicKeyParameters ed448PublicKey)
        {
            _algorithm = DnssecAlgorithm.ED448;
            _ed448PublicKey = ed448PublicKey;

            _rawPublicKey = _ed448PublicKey.GetEncoded();
        }

        public DnssecEddsaPublicKey(byte[] rawPublicKey, DnssecAlgorithm algorithm)
            : base(rawPublicKey)
        {
            _algorithm = algorithm;

            switch (_algorithm)
            {
                case DnssecAlgorithm.ED25519:
                    _ed25519PublicKey = new Ed25519PublicKeyParameters(rawPublicKey);
                    break;

                case DnssecAlgorithm.ED448:
                    _ed448PublicKey = new Ed448PublicKeyParameters(rawPublicKey);
                    break;

                default:
                    throw new InvalidOperationException();
            }
        }

        #endregion

        #region public

        public override bool IsSignatureValid(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm)
        {
            ISigner signer;

            switch (_algorithm)
            {
                case DnssecAlgorithm.ED25519:
                    signer = new Ed25519Signer();
                    signer.Init(false, _ed25519PublicKey);
                    break;

                case DnssecAlgorithm.ED448:
                    signer = new Ed448Signer([]);
                    signer.Init(false, _ed448PublicKey);
                    break;

                default:
                    throw new InvalidOperationException();
            }

            signer.BlockUpdate(hash);

            return signer.VerifySignature(signature);
        }

        #endregion

        #region properties

        public override bool IsAlgorithmSupported
        { get { return true; } }

        #endregion
    }
}
