/*
Technitium Library
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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

using System.Security.Cryptography;

namespace TechnitiumLibrary.Security.Cryptography
{
    public enum KeyAgreementKeyDerivationFunction
    {
        Unknown = 0,
        Hash = 1,
        Hmac = 2
    }

    public enum KeyAgreementKeyDerivationHashAlgorithm
    {
        Unknown = 0,
        SHA256 = 1,
        SHA384 = 2,
        SHA512 = 3
    }

    public abstract class KeyAgreement
    {
        #region variables

        readonly KeyAgreementKeyDerivationFunction _kdFunc = KeyAgreementKeyDerivationFunction.Hash;
        readonly KeyAgreementKeyDerivationHashAlgorithm _kdHashAlgo = KeyAgreementKeyDerivationHashAlgorithm.SHA256;
        byte[] _hmacKey;

        #endregion

        #region constructor

        public KeyAgreement(KeyAgreementKeyDerivationFunction kdFunc, KeyAgreementKeyDerivationHashAlgorithm kdHashAlgo)
        {
            _kdFunc = kdFunc;
            _kdHashAlgo = kdHashAlgo;
        }

        #endregion

        #region public

        public byte[] DeriveKeyMaterial(byte[] otherPartyPublicKey)
        {
            switch (_kdFunc)
            {
                case KeyAgreementKeyDerivationFunction.Hash:
                    switch (_kdHashAlgo)
                    {
                        case KeyAgreementKeyDerivationHashAlgorithm.SHA256:
                            using (HashAlgorithm hash = HashAlgorithm.Create("SHA256"))
                            {
                                return hash.ComputeHash(ComputeKey(otherPartyPublicKey));
                            }

                        case KeyAgreementKeyDerivationHashAlgorithm.SHA384:
                            using (HashAlgorithm hash = HashAlgorithm.Create("SHA384"))
                            {
                                return hash.ComputeHash(ComputeKey(otherPartyPublicKey));
                            }

                        case KeyAgreementKeyDerivationHashAlgorithm.SHA512:
                            using (HashAlgorithm hash = HashAlgorithm.Create("SHA512"))
                            {
                                return hash.ComputeHash(ComputeKey(otherPartyPublicKey));
                            }

                        default:
                            throw new CryptoException("Key derivation hash algorithm not supported.");
                    }

                case KeyAgreementKeyDerivationFunction.Hmac:
                    switch (_kdHashAlgo)
                    {
                        case KeyAgreementKeyDerivationHashAlgorithm.SHA256:
                            using (HMAC hmac = new HMACSHA256(_hmacKey))
                            {
                                return hmac.ComputeHash(ComputeKey(otherPartyPublicKey));
                            }

                        case KeyAgreementKeyDerivationHashAlgorithm.SHA384:
                            using (HMAC hmac = new HMACSHA384(_hmacKey))
                            {
                                return hmac.ComputeHash(ComputeKey(otherPartyPublicKey));
                            }

                        case KeyAgreementKeyDerivationHashAlgorithm.SHA512:
                            using (HMAC hmac = new HMACSHA512(_hmacKey))
                            {
                                return hmac.ComputeHash(ComputeKey(otherPartyPublicKey));
                            }

                        default:
                            throw new CryptoException("Key derivation hash algorithm not supported.");
                    }

                default:
                    throw new CryptoException("Key derivation function not supported.");
            }
        }

        #endregion

        #region abstract

        public abstract byte[] GetPublicKey();

        protected abstract byte[] ComputeKey(byte[] otherPartyPublicKey);

        #endregion

        #region properties

        public KeyAgreementKeyDerivationFunction KeyDerivationFunction
        { get { return _kdFunc; } }

        public KeyAgreementKeyDerivationHashAlgorithm KeyDerivationHashAlgorithm
        { get { return _kdHashAlgo; } }

        public byte[] HmacKey
        {
            get { return _hmacKey; }
            set { _hmacKey = value; }
        }

        #endregion
    }
}
