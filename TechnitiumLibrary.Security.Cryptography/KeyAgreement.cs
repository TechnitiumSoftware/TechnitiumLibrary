/*
Technitium Library
Copyright (C) 2016  Shreyas Zare (shreyas@technitium.com)

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
    public enum KeyAgreementAlgorithm
    {
        Unknown = 0,
        DiffieHellman = 1,
        ECDiffieHellman = 2
    }

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

        KeyAgreementKeyDerivationFunction _kdFunc = KeyAgreementKeyDerivationFunction.Hash;
        KeyAgreementKeyDerivationHashAlgorithm _kdHashAlgo = KeyAgreementKeyDerivationHashAlgorithm.SHA256;
        byte[] _hmacMessage;

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
            HashAlgorithm hash;

            switch (_kdHashAlgo)
            {
                case KeyAgreementKeyDerivationHashAlgorithm.SHA256:
                    hash = HashAlgorithm.Create("SHA256");
                    break;

                case KeyAgreementKeyDerivationHashAlgorithm.SHA384:
                    hash = HashAlgorithm.Create("SHA384");
                    break;

                case KeyAgreementKeyDerivationHashAlgorithm.SHA512:
                    hash = HashAlgorithm.Create("SHA512");
                    break;

                default:
                    throw new CryptoException("Key derivation hash algorithm not supported.");
            }

            try
            {
                switch (_kdFunc)
                {
                    case KeyAgreementKeyDerivationFunction.Hash:
                        return hash.ComputeHash(ComputeKey(otherPartyPublicKey));

                    case KeyAgreementKeyDerivationFunction.Hmac:
                        return hash.ComputeHash(_hmacMessage);

                    default:
                        throw new CryptoException("Key derivation function not supported.");
                }
            }
            finally
            {
                hash.Dispose();
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

        public byte[] HmacMessage
        {
            get { return _hmacMessage; }
            set { _hmacMessage = value; }
        }

        #endregion
    }
}
