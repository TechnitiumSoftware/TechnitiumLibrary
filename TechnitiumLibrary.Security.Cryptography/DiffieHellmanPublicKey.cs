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

using System;
using System.IO;
using System.Numerics;
using System.Text;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Security.Cryptography
{
    public class DiffieHellmanPublicKey
    {
        #region variables

        DiffieHellmanGroupType _group;
        int _keySize;
        BigInteger _p;
        BigInteger _g;
        BigInteger _x;

        #endregion

        #region constructor

        public DiffieHellmanPublicKey(DiffieHellmanGroupType group, int keySize, BigInteger x)
        {
            _group = group;
            _keySize = keySize;
            _x = x;

            DiffieHellmanGroup dhg = DiffieHellmanGroup.GetGroup(group, keySize);
            VerifyPublicKey(_keySize, dhg.P, dhg.G, x);
        }

        public DiffieHellmanPublicKey(int keySize, BigInteger p, BigInteger g, BigInteger x)
        {
            _group = DiffieHellmanGroupType.None;
            _keySize = keySize;
            _p = p;
            _g = g;
            _x = x;

            VerifyPublicKey(_keySize, _p, _g, _x);
        }

        public DiffieHellmanPublicKey(byte[] publicKey)
        {
            using (MemoryStream mS = new MemoryStream(publicKey, false))
            {
                BinaryReader bR = new BinaryReader(mS);

                if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "DH")
                    throw new InvalidDataException("Invalid DiffieHellmanPublicKey data format.");

                switch (bR.ReadByte()) //version
                {
                    case 2:
                        _keySize = bR.ReadInt32();
                        _group = (DiffieHellmanGroupType)bR.ReadByte();

                        switch (_group)
                        {
                            case DiffieHellmanGroupType.RFC3526:
                                DiffieHellmanGroup dhg = DiffieHellmanGroup.GetGroup(_group, _keySize);
                                _p = dhg.P;
                                _g = dhg.G;
                                _x = ReadPositiveNumber(bR.ReadBuffer());
                                break;

                            case DiffieHellmanGroupType.None:
                                _p = ReadPositiveNumber(bR.ReadBuffer());
                                _g = ReadPositiveNumber(bR.ReadBuffer());
                                _x = ReadPositiveNumber(bR.ReadBuffer());
                                break;

                            default:
                                throw new NotSupportedException("DiffieHellmanGroup type not supported.");
                        }

                        break;

                    default:
                        throw new InvalidDataException("DiffieHellmanPublicKey data format version not supported.");
                }
            }

            VerifyPublicKey(_keySize, _p, _g, _x);
        }

        #endregion

        #region private

        private static BigInteger ReadPositiveNumber(byte[] buffer)
        {
            if (buffer[buffer.Length - 1] == 0)
                return new BigInteger(buffer);

            byte[] buffer2 = new byte[buffer.Length + 1];
            Buffer.BlockCopy(buffer, 0, buffer2, 0, buffer.Length);
            return new BigInteger(buffer2);
        }

        private static void VerifyPublicKey(int keySize, BigInteger p, BigInteger g, BigInteger x)
        {
            if ((keySize - (p.ToByteArray().Length << 3)) > 32)
                throw new CryptoException("DiffieHellman invalid public key parameter.");

            BigInteger pm2 = p - 2;

            if ((x < 2) || (x > pm2))
                throw new CryptoException("DiffieHellman invalid public key parameter.");

            if ((g < 2) || (g > pm2))
                throw new CryptoException("DiffieHellman invalid public key parameter.");
        }

        #endregion

        #region public

        public byte[] PublicKey()
        {
            using (MemoryStream mS = new MemoryStream(4096))
            {
                BinaryWriter bW = new BinaryWriter(mS);

                bW.Write(Encoding.ASCII.GetBytes("DH"));
                bW.Write((byte)2);

                bW.Write(_keySize);
                bW.Write((byte)_group);

                switch (_group)
                {
                    case DiffieHellmanGroupType.RFC3526:
                        bW.WriteBuffer(_x.ToByteArray());
                        break;

                    default:
                        bW.WriteBuffer(_p.ToByteArray());
                        bW.WriteBuffer(_g.ToByteArray());
                        bW.WriteBuffer(_x.ToByteArray());
                        break;
                }

                return mS.ToArray();
            }
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

        public BigInteger X
        { get { return _x; } }

        #endregion
    }
}
