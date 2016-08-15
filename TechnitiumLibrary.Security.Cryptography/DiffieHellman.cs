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

using System.Numerics;
using System.Security.Cryptography;

namespace TechnitiumLibrary.Security.Cryptography
{
    public class DiffieHellman : KeyAgreement
    {
        #region variables

        static RandomNumberGenerator _rnd = new RNGCryptoServiceProvider();

        DiffieHellmanGroupType _group;
        int _keySize;

        BigInteger _p;
        BigInteger _g;
        BigInteger _privateKey;

        #endregion

        #region constructor

        public DiffieHellman(DiffieHellmanGroupType group, int keySize, KeyAgreementKeyDerivationFunction kdFunc, KeyAgreementKeyDerivationHashAlgorithm kdHashAlgo)
            : base(kdFunc, kdHashAlgo)
        {
            _group = group;
            _keySize = keySize;

            DiffieHellmanGroup dhg = DiffieHellmanGroup.GetGroup(_group, _keySize);

            _p = dhg.P;
            _g = dhg.G;

            GeneratePrivateKey();
        }

        public DiffieHellman(DiffieHellmanPublicKey publicKey, KeyAgreementKeyDerivationFunction kdFunc, KeyAgreementKeyDerivationHashAlgorithm kdHashAlgo)
            : base(kdFunc, kdHashAlgo)
        {
            _keySize = publicKey.KeySize;

            _p = publicKey.P;
            _g = publicKey.G;

            GeneratePrivateKey();
        }

        #endregion

        #region private

        private void GeneratePrivateKey()
        {
            byte[] p = _p.ToByteArray();
            byte[] buffer = new byte[p.Length - 1];

            _rnd.GetBytes(buffer);
            buffer[buffer.Length - 1] &= 0x7F; //to keep BigInteger positive
            _privateKey = new BigInteger(buffer);

            BigInteger pm2 = _p - 2;
            while (_privateKey > pm2)
            {
                _privateKey >>= 1;
            }
        }

        #endregion

        #region public

        public override byte[] GetPublicKey()
        {
            if (_group == DiffieHellmanGroupType.None)
                return (new DiffieHellmanPublicKey(_keySize, _p, _g, BigInteger.ModPow(_g, _privateKey, _p))).PublicKey();
            else
                return (new DiffieHellmanPublicKey(_group, _keySize, BigInteger.ModPow(_g, _privateKey, _p))).PublicKey();
        }

        #endregion

        #region protected

        protected override byte[] ComputeKey(byte[] otherPartyPublicKey)
        {
            DiffieHellmanPublicKey opPublicKey = new DiffieHellmanPublicKey(otherPartyPublicKey);

            if (opPublicKey.Group != _group)
                throw new CryptoException("DiffieHellman group mismatch.");

            if (opPublicKey.KeySize != _keySize)
                throw new CryptoException("DiffieHellman key size mismatch.");

            if (opPublicKey.P != _p)
                throw new CryptoException("DiffieHellman public key parameter P doesn't match.");

            if (opPublicKey.G != _g)
                throw new CryptoException("DiffieHellman public key parameter G doesn't match.");

            HashAlgorithm hash;

            switch (base.KeyDerivationHashAlgorithm)
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
                    throw new CryptoException("Hash algorithm not supported.");
            }

            return hash.ComputeHash(BigInteger.ModPow(opPublicKey.X, _privateKey, _p).ToByteArray());
        }

        #endregion

        #region properties

        public DiffieHellmanGroupType Group
        { get { return _group; } }

        public int KeySize
        { get { return _keySize; } }

        public BigInteger P
        { get { return _p; } }

        public BigInteger G
        { get { return _g; } }

        #endregion
    }
}
