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

namespace TechnitiumLibrary.Security.Cryptography
{
    public abstract class CryptoContainer : IDisposable
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

        public CryptoContainer(string file, string password = null)
        {
            using (FileStream fS = new FileStream(file, FileMode.Open, FileAccess.Read))
            {
                ReadFrom(fS, password);
            }
        }

        public CryptoContainer(Stream s, string password = null)
        {
            ReadFrom(s, password);
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            Dispose(true);
        }

        bool _disposed = false;

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_containerKey != null)
                    _containerKey.Dispose();

                if (_kdf != null)
                    _kdf.Dispose();

                if (_hmac != null)
                    _hmac.Dispose();
            }

            _disposed = true;
        }

        #endregion

        #region protected abstract

        private void ReadFrom(Stream s, string password)
        {
            byte[] format = new byte[2];
            s.Read(format, 0, 2);

            if (Encoding.ASCII.GetString(format) != "CC")
                throw new InvalidCryptoContainerException("Invalid CryptoContainer format.");

            switch (s.ReadByte()) //version
            {
                case 0:
                    ReadPlainTextFrom(s);
                    break;

                case 1: //depricated version
                    {
                        if (password == null)
                            throw new InvalidCryptoContainerException("Password required.");

                        //CryptoAlgo
                        SymmetricEncryptionAlgorithm cryptoAlgo = (SymmetricEncryptionAlgorithm)s.ReadByte();

                        //KeySizeBytes
                        int keySizeBytes = s.ReadByte();

                        byte[] IV = new byte[s.ReadByte()];
                        s.Read(IV, 0, IV.Length);

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
                        ReadPlainTextFrom(_containerKey.GetCryptoStreamReader(s));

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
                        SymmetricEncryptionAlgorithm cryptoAlgo = (SymmetricEncryptionAlgorithm)s.ReadByte();

                        //KeySizeBytes
                        int keySizeBytes = s.ReadByte();

                        byte[] IV = new byte[s.ReadByte()];
                        s.Read(IV, 0, IV.Length);

                        byte[] salt = new byte[s.ReadByte()];
                        s.Read(salt, 0, salt.Length);

                        byte[] HMAC = new byte[s.ReadByte()];
                        s.Read(HMAC, 0, HMAC.Length);

                        _kdf = PBKDF2.CreateHMACSHA256(password, salt, PBKDF2_ITERATION_COUNT);
                        byte[] key = _kdf.GetBytes(keySizeBytes);

                        //authenticate data
                        _hmac = new HMACSHA256(key);
                        long startPosition = s.Position;
                        byte[] computedHMAC = _hmac.ComputeHash(s);
                        s.Position = startPosition;

                        //verify hmac
                        for (int i = 0; i < HMAC.Length; i++)
                        {
                            if (HMAC[i] != computedHMAC[i])
                                throw new CryptoException("Invalid password or data tampered.");
                        }

                        //decrypt data
                        _containerKey = new SymmetricCryptoKey(cryptoAlgo, key, IV);
                        ReadPlainTextFrom(_containerKey.GetCryptoStreamReader(s));
                    }
                    break;

                case -1:
                    throw new EndOfStreamException();

                default:
                    throw new InvalidCryptoContainerException("CryptoContainer format version not supported.");
            }
        }

        protected abstract void ReadPlainTextFrom(Stream s);

        protected abstract void WritePlainTextTo(Stream s);

        #endregion

        #region public

        public void SaveAs(string file)
        {
            using (FileStream fS = new FileStream(file, FileMode.Create, FileAccess.ReadWrite))
            {
                WriteTo(fS);
            }
        }

        public void WriteTo(Stream s)
        {
            s.Write(Encoding.ASCII.GetBytes("CC"), 0, 2); //format

            if (_containerKey == null)
            {
                s.WriteByte((byte)0); //version 0 = plain text
                WritePlainTextTo(s);
            }
            else
            {
                s.WriteByte(2); //version uses PBKDF2-HMAC-SHA256
                s.WriteByte((byte)_containerKey.Algorithm); //CryptoAlgoName
                s.WriteByte(Convert.ToByte(_containerKey.KeySize / 8)); //KeySizeBytes
                s.WriteByte(Convert.ToByte(_containerKey.IV.Length)); //IV Size
                s.Write(_containerKey.IV, 0, _containerKey.IV.Length); //IV
                s.WriteByte(Convert.ToByte(_kdf.Salt.Length)); //salt size
                s.Write(_kdf.Salt, 0, _kdf.Salt.Length); //salt

                //write placeholder for HMAC
                byte[] computedHMAC = new byte[32];
                s.WriteByte(32);
                long hmacPosition = s.Position;
                s.Write(computedHMAC, 0, 32);
                long cipherPosition = s.Position;

                //encrypt data
                CryptoStream c = _containerKey.GetCryptoStreamWriter(s);
                BufferedStream bS = new BufferedStream(c, 16384);
                WritePlainTextTo(bS);
                bS.Flush();
                c.FlushFinalBlock();

                //compute HMAC and write it into placeholder
                s.Position = cipherPosition;
                computedHMAC = _hmac.ComputeHash(s);

                s.Position = hmacPosition;
                s.Write(computedHMAC, 0, 32);
            }
        }

        public void SetPassword(SymmetricEncryptionAlgorithm cryptoAlgo, int keySize, string password)
        {
            int keySizeBytes = keySize / 8;
            _kdf = PBKDF2.CreateHMACSHA256(password, keySizeBytes, PBKDF2_ITERATION_COUNT);
            byte[] key = _kdf.GetBytes(keySizeBytes);

            _containerKey = new SymmetricCryptoKey(cryptoAlgo, key);
            _hmac = new HMACSHA256(key);
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
