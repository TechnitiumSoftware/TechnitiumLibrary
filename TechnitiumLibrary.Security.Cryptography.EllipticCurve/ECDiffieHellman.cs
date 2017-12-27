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
    //wrapper class for .NET ECDiffieHellmanCng
    public class ECDiffieHellman : KeyAgreement
    {
        #region variables

        object _ecdh;

        #endregion

        #region constructor

        public ECDiffieHellman(int keySize, KeyAgreementKeyDerivationFunction kdFunc, KeyAgreementKeyDerivationHashAlgorithm hashAlgo)
            : base(kdFunc, hashAlgo)
        {
            ECDiffieHellmanCng ecdh = new ECDiffieHellmanCng(keySize);
            ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;

            switch (hashAlgo)
            {
                case KeyAgreementKeyDerivationHashAlgorithm.SHA256:
                    ecdh.HashAlgorithm = CngAlgorithm.Sha256;
                    break;

                case KeyAgreementKeyDerivationHashAlgorithm.SHA384:
                    ecdh.HashAlgorithm = CngAlgorithm.Sha384;
                    break;

                case KeyAgreementKeyDerivationHashAlgorithm.SHA512:
                    ecdh.HashAlgorithm = CngAlgorithm.Sha512;
                    break;

                default:
                    throw new CryptoException("Key derivation hash algorithm not supported.");
            }

            _ecdh = ecdh;
        }

        #endregion

        #region overrides

        public override byte[] GetPublicKey()
        {
            return ((ECDiffieHellmanCng)_ecdh).PublicKey.ToByteArray();
        }

        protected override byte[] ComputeKey(byte[] otherPartyPublicKey)
        {
            return ((ECDiffieHellmanCng)_ecdh).DeriveKeyMaterial(ECDiffieHellmanCngPublicKey.FromByteArray(otherPartyPublicKey, CngKeyBlobFormat.EccPublicBlob));
        }

        #endregion
    }
}
