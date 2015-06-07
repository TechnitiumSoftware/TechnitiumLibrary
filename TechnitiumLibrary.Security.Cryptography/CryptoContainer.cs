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

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Security.Cryptography
{
    public abstract class CryptoContainer : WriteStream
    {
        #region variables

        const int PBKDF2_ITERATION_COUNT = 200000;

        SymmetricCryptoKey _containerKey;
        PBKDF2 _kdf;
        HMAC _hmac;

        #endregion

        #region constructor

        public CryptoContainer()
        { }

        public CryptoContainer(SymmetricEncryptionAlgorithm cryptoAlgo, int keySize, string password)
        {
            SetPassword(cryptoAlgo, keySize, password);
        }

        public CryptoContainer(Stream s, string password = null)
        {
            ReadFrom(new BinaryReader(s), password);
        }

        public CryptoContainer(BinaryReader bR, string password = null)
        {
            ReadFrom(bR, password);
        }

        #endregion

        #region protected abstract

        private void ReadFrom(BinaryReader bR, string password = null)
        {
            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "CC")
                throw new InvalidCryptoContainerException("Invalid CryptoContainer format.");

            byte version = bR.ReadByte();

            switch (version) //version
            {
                case 0:
                    ReadPlainTextFrom(bR);
                    break;

                case 1: //depricated version
                    {
                        if (password == null)
                            throw new InvalidCryptoContainerException("Password required.");

                        //CryptoAlgo
                        SymmetricEncryptionAlgorithm cryptoAlgo = (SymmetricEncryptionAlgorithm)bR.ReadByte();

                        //KeySizeBytes
                        int keySizeBytes = bR.ReadByte();

                        byte[] IV = bR.ReadBytes(bR.ReadByte());
                        byte[] key;

                        switch (keySizeBytes)
                        {
                            case 16:
                                key = HashAlgorithm.Create("MD5").ComputeHash(Encoding.UTF8.GetBytes(password));
                                break;

                            case 32:
                                key = HashAlgorithm.Create("SHA256").ComputeHash(Encoding.UTF8.GetBytes(password));
                                break;

                            default:
                                throw new CryptoException("CryptoContainer key size not supported.");
                        }

                        _containerKey = new SymmetricCryptoKey(cryptoAlgo, key, IV);
                        ReadPlainTextFrom(new BinaryReader(_containerKey.GetCryptoStreamReader(bR.BaseStream)));

                        //auto upgrade to version 2 with PBKDF2-HMAC-SHA256 when calling WriteTo
                        _kdf = PBKDF2.CreateHMACSHA256(password, keySizeBytes, PBKDF2_ITERATION_COUNT);
                        key = _kdf.GetBytes(keySizeBytes);
                        _containerKey = new SymmetricCryptoKey(cryptoAlgo, key, IV);
                        _hmac = new HMACSHA256(key);
                    }
                    break;

                case 2: //using PBKDF2-HMAC-SHA256
                    {
                        if (password == null)
                            throw new InvalidCryptoContainerException("Password required.");

                        //CryptoAlgo
                        SymmetricEncryptionAlgorithm cryptoAlgo = (SymmetricEncryptionAlgorithm)bR.ReadByte();

                        //KeySizeBytes
                        int keySizeBytes = bR.ReadByte();

                        byte[] IV = bR.ReadBytes(bR.ReadByte());
                        byte[] salt = bR.ReadBytes(bR.ReadByte());
                        byte[] HMAC = bR.ReadBytes(bR.ReadByte());
                        _kdf = PBKDF2.CreateHMACSHA256(password, salt, PBKDF2_ITERATION_COUNT);
                        byte[] key = _kdf.GetBytes(keySizeBytes);

                        //authenticate data
                        _hmac = new HMACSHA256(key);
                        long startPosition = bR.BaseStream.Position;
                        byte[] computedHMAC = _hmac.ComputeHash(bR.BaseStream);
                        bR.BaseStream.Position = startPosition;

                        //verify hmac
                        for (int i = 0; i < HMAC.Length; i++)
                        {
                            if (HMAC[i] != computedHMAC[i])
                                throw new CryptoException("Invalid password or data tampered.");
                        }

                        //decrypt data
                        _containerKey = new SymmetricCryptoKey(cryptoAlgo, key, IV);
                        ReadPlainTextFrom(new BinaryReader(_containerKey.GetCryptoStreamReader(bR.BaseStream)));
                    }
                    break;

                default:
                    throw new InvalidCryptoContainerException("CryptoContainer format version not supported.");
            }
        }

        protected abstract void ReadPlainTextFrom(BinaryReader bR);

        protected abstract void WritePlainTextTo(BinaryWriter bW);

        #endregion

        #region public

        public sealed override void WriteTo(BinaryWriter bW)
        {
            bW.Write(Encoding.ASCII.GetBytes("CC"), 0, 2); //format

            if (_containerKey == null)
            {
                bW.Write((byte)0); //version 0 = plain text
                WritePlainTextTo(bW);
            }
            else
            {
                bW.Flush();
                Stream baseStream = bW.BaseStream;

                baseStream.WriteByte(2); //version uses PBKDF2-HMAC-SHA256
                baseStream.WriteByte((byte)_containerKey.Algorithm); //CryptoAlgoName
                baseStream.WriteByte(Convert.ToByte(_containerKey.KeySize / 8)); //KeySizeBytes
                baseStream.WriteByte(Convert.ToByte(_containerKey.IV.Length)); //IV Size
                baseStream.Write(_containerKey.IV, 0, _containerKey.IV.Length); //IV
                baseStream.WriteByte(Convert.ToByte(_kdf.Salt.Length)); //salt size
                baseStream.Write(_kdf.Salt, 0, _kdf.Salt.Length); //salt

                //write placeholder for HMAC
                byte[] computedHMAC = new byte[32];
                baseStream.WriteByte(32);
                long hmacPosition = baseStream.Position;
                baseStream.Write(computedHMAC, 0, 32);
                long cipherPosition = baseStream.Position;

                //encrypt data
                CryptoStream c = _containerKey.GetCryptoStreamWriter(baseStream);

                BinaryWriter bW2 = new BinaryWriter(c);
                WritePlainTextTo(bW2);
                bW2.Flush();

                c.FlushFinalBlock();

                //compute HMAC and write it into placeholder
                baseStream.Position = cipherPosition;
                computedHMAC = _hmac.ComputeHash(baseStream);

                baseStream.Position = hmacPosition;
                baseStream.Write(computedHMAC, 0, 32);
            }
        }

        public void SetPassword(SymmetricEncryptionAlgorithm cryptoAlgo, int keySize, string password)
        {
            int keySizeBytes = keySize / 8;
            _kdf = PBKDF2.CreateHMACSHA256(password, keySizeBytes, PBKDF2_ITERATION_COUNT);
            byte[] key = _kdf.GetBytes(keySizeBytes);

            _containerKey = new SymmetricCryptoKey(cryptoAlgo, key);
        }

        public void ChangePassword(string password = null)
        {
            if (_containerKey == null)
                throw new CryptoException("Cannot change password. Use SetPassword() instead.");

            if (password == null)
                _containerKey = null;
            else
                SetPassword(_containerKey.Algorithm, _containerKey.KeySize, password);
        }

        #endregion
    }
}
