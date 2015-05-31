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
    //wrapper class for .NET ECDiffieHellmanCng
    public class ECDiffieHellman : KeyAgreement
    {
        #region variables

        ECDiffieHellmanCng _ecdh;

        #endregion

        #region constructor

        public ECDiffieHellman(int keySize, KeyDerivationHashAlgorithm hashAlgo)
        {
            _ecdh = new ECDiffieHellmanCng(keySize);
            _ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;

            switch (hashAlgo)
            {
                case KeyDerivationHashAlgorithm.SHA256:
                    _ecdh.HashAlgorithm = CngAlgorithm.Sha256;
                    break;

                case KeyDerivationHashAlgorithm.SHA384:
                    _ecdh.HashAlgorithm = CngAlgorithm.Sha384;
                    break;

                case KeyDerivationHashAlgorithm.SHA512:
                    _ecdh.HashAlgorithm = CngAlgorithm.Sha512;
                    break;

                default:
                    throw new CryptoException("Key derivation hash algorithm not supported.");
            }
        }

        #endregion

        #region overrides

        public override string GetPublicKeyXML()
        {
            return _ecdh.PublicKey.ToXmlString();
        }

        protected override byte[] ComputeKey(string otherPartyPublicKeyXML)
        {
            return _ecdh.DeriveKeyMaterial(ECDiffieHellmanCngPublicKey.FromXmlString(otherPartyPublicKeyXML));
        }

        #endregion
    }
}
