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

using System.Security.Cryptography;

namespace TechnitiumLibrary.Security.Cryptography
{
    public enum KeyAgreementAlgorithm
    {
        Unknown = 0,
        DiffieHellman = 1,
        ECDiffieHellman = 2
    }

    public enum KeyDerivationFunction
    {
        Unknown = 0,
        Hash = 1,
        Hmac = 2
    }

    public enum KeyDerivationHashAlgorithm
    {
        Unknown = 0,
        SHA256 = 1,
        SHA384 = 2,
        SHA512 = 3
    }

    public abstract class KeyAgreement
    {
        #region variables

        KeyDerivationFunction _kdFunc = KeyDerivationFunction.Hash;
        KeyDerivationHashAlgorithm _kdAlgo = KeyDerivationHashAlgorithm.SHA256;
        byte[] _hmacMessage;

        #endregion

        #region static

        public static KeyAgreement Create(KeyAgreementAlgorithm algo, int keySize, KeyDerivationFunction kdFunc = KeyDerivationFunction.Hash, KeyDerivationHashAlgorithm kdAlgo = KeyDerivationHashAlgorithm.SHA256)
        {
            switch (algo)
            {
                case KeyAgreementAlgorithm.DiffieHellman:
                    return new DiffieHellman(keySize, kdAlgo) { _kdAlgo = kdAlgo, _kdFunc = kdFunc };

                case KeyAgreementAlgorithm.ECDiffieHellman:
                    return new ECDiffieHellman(keySize, kdAlgo) { _kdAlgo = kdAlgo, _kdFunc = kdFunc };

                default:
                    throw new CryptoException("KeyExchange algorithm not supported.");
            }
        }

        #endregion

        #region public

        public byte[] DeriveKeyMaterial(string otherPartyPublicKeyXML)
        {
            HashAlgorithm hash;

            switch (_kdFunc)
            {
                case KeyDerivationFunction.Hash:
                    switch (_kdAlgo)
                    {
                        case KeyDerivationHashAlgorithm.SHA256:
                            hash = HashAlgorithm.Create("SHA256");
                            break;

                        case KeyDerivationHashAlgorithm.SHA384:
                            hash = HashAlgorithm.Create("SHA384");
                            break;

                        case KeyDerivationHashAlgorithm.SHA512:
                            hash = HashAlgorithm.Create("SHA512");
                            break;

                        default:
                            throw new CryptoException("Key derivation hash algorithm not supported.");
                    }

                    return hash.ComputeHash(ComputeKey(otherPartyPublicKeyXML));

                case KeyDerivationFunction.Hmac:
                    switch (_kdAlgo)
                    {
                        case KeyDerivationHashAlgorithm.SHA256:
                            hash = new HMACSHA256(ComputeKey(otherPartyPublicKeyXML));
                            break;

                        case KeyDerivationHashAlgorithm.SHA384:
                            hash = new HMACSHA384(ComputeKey(otherPartyPublicKeyXML));
                            break;

                        case KeyDerivationHashAlgorithm.SHA512:
                            hash = new HMACSHA512(ComputeKey(otherPartyPublicKeyXML));
                            break;

                        default:
                            throw new CryptoException("Key derivation hash algorithm not supported.");
                    }

                    return hash.ComputeHash(_hmacMessage);

                default:
                    throw new CryptoException("Key derivation function not supported.");
            }
        }

        #endregion

        #region abstract

        public abstract string GetPublicKeyXML();

        protected abstract byte[] ComputeKey(string otherPartyPublicKeyXML);

        #endregion

        #region properties

        public KeyDerivationFunction KeyDerivationFunction
        { get { return _kdFunc; } }

        public KeyDerivationHashAlgorithm KeyDerivationAlgorithm
        { get { return _kdAlgo; } }

        public byte[] HmacMessage
        {
            get { return _hmacMessage; }
            set { _hmacMessage = value; }
        }

        #endregion
    }
}
