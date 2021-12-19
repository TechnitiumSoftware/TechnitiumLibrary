/*
Technitium Library
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [Flags]
    public enum DnsDnsKeyFlag : ushort
    {
        ZoneKey = 0x100,
        SecureEntryPoint = 0x1,
        Revoke = 0x80
    }

    public enum DnssecAlgorithm : byte
    {
        Unknown = 0,
        RSAMD5 = 1,
        DSA = 3,
        RSASHA1 = 5,
        DSA_NSEC3_SHA1 = 6,
        RSASHA1_NSEC3_SHA1 = 7,
        RSASHA256 = 8,
        RSASHA512 = 10,
        ECC_GOST = 12,
        ECDSAP256SHA256 = 13,
        ECDSAP384SHA384 = 14,
        ED25519 = 15,
        ED448 = 16,
        PRIVATEDNS = 253,
        PRIVATEOID = 254
    }

    public class DnsDNSKEYRecord : DnsResourceRecordData
    {
        #region variables

        DnsDnsKeyFlag _flags;
        byte _protocol;
        DnssecAlgorithm _algorithm;
        DnssecPublicKey _publicKey;

        ushort _computedKeyTag;

        byte[] _rData;

        #endregion

        #region constructors

        public DnsDNSKEYRecord(DnsDnsKeyFlag flags, byte protocol, DnssecAlgorithm algorithm, DnssecPublicKey publicKey)
        {
            _flags = flags;
            _protocol = protocol;
            _algorithm = algorithm;
            _publicKey = publicKey;

            Serialize();
            ComputeKeyTag();
        }

        public DnsDNSKEYRecord(Stream s)
            : base(s)
        { }

        public DnsDNSKEYRecord(dynamic jsonResourceRecord)
        {
            _rdLength = Convert.ToUInt16(jsonResourceRecord.data.Value.Length);

            string[] parts = (jsonResourceRecord.data.Value as string).Split(' ');

            _flags = Enum.Parse<DnsDnsKeyFlag>(parts[0], true);
            _protocol = byte.Parse(parts[1]);
            _algorithm = Enum.Parse<DnssecAlgorithm>(parts[2].Replace("-", "_"), true);
            _publicKey = DnssecPublicKey.Parse(_algorithm, Convert.FromBase64String(parts[3]));

            Serialize();
            ComputeKeyTag();
        }

        #endregion

        #region private

        private void Serialize()
        {
            using (MemoryStream mS = new MemoryStream())
            {
                DnsDatagram.WriteUInt16NetworkOrder((ushort)_flags, mS);
                mS.WriteByte(_protocol);
                mS.WriteByte((byte)_algorithm);
                _publicKey.WriteTo(mS);

                _rData = mS.ToArray();
            }
        }

        private void ComputeKeyTag()
        {
            switch (_algorithm)
            {
                case DnssecAlgorithm.RSAMD5:
                    byte[] buffer = new byte[2];
                    Buffer.BlockCopy(_publicKey.RawPublicKey, _publicKey.RawPublicKey.Length - 3, buffer, 0, 2);
                    Array.Reverse(buffer);
                    _computedKeyTag = BitConverter.ToUInt16(buffer);
                    break;

                default:
                    uint ac = 0;

                    for (int i = 0; i < _rData.Length; i++)
                    {
                        if ((i & 1) > 0)
                            ac += _rData[i];
                        else
                            ac += (uint)(_rData[i] << 8);
                    }

                    ac += (ac >> 16) & 0xFFFF;

                    _computedKeyTag = (ushort)(ac & 0xFFFFu);
                    break;
            }
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _rData = s.ReadBytes(_rdLength);

            using (MemoryStream mS = new MemoryStream(_rData))
            {
                _flags = (DnsDnsKeyFlag)DnsDatagram.ReadUInt16NetworkOrder(mS);
                _protocol = mS.ReadByteValue();
                _algorithm = (DnssecAlgorithm)mS.ReadByteValue();
                _publicKey = DnssecPublicKey.Parse(_algorithm, mS.ReadBytes(_rdLength - 2 - 1 - 1));
            }

            ComputeKeyTag();
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            s.Write(_rData);
        }

        #endregion

        #region public

        public bool IsDnsKeyValid(string ownerName, DnsDSRecord ds)
        {
            byte[] computedDigest;

            using (MemoryStream mS = new MemoryStream(DnsDatagram.GetSerializeDomainNameLength(ownerName) + _rData.Length))
            {
                DnsDatagram.SerializeDomainName(ownerName.ToLower(), mS);
                mS.Write(_rData);

                mS.Position = 0;

                switch (ds.DigestType)
                {
                    case DnssecDigestType.SHA1:
                        using (HashAlgorithm hashAlgo = SHA1.Create())
                        {
                            computedDigest = hashAlgo.ComputeHash(mS);
                        }
                        break;

                    case DnssecDigestType.SHA256:
                        using (HashAlgorithm hashAlgo = SHA256.Create())
                        {
                            computedDigest = hashAlgo.ComputeHash(mS);
                        }
                        break;

                    case DnssecDigestType.SHA384:
                        using (HashAlgorithm hashAlgo = SHA384.Create())
                        {
                            computedDigest = hashAlgo.ComputeHash(mS);
                        }
                        break;

                    default:
                        return false; //hash not supported
                }
            }

            return BinaryNumber.Equals(computedDigest, ds.DigestValue);
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsDNSKEYRecord other)
            {
                if (_flags != other._flags)
                    return false;

                if (_protocol != other._protocol)
                    return false;

                if (_algorithm != other._algorithm)
                    return false;

                if (!BinaryNumber.Equals(_publicKey.RawPublicKey, other._publicKey.RawPublicKey))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_flags, _protocol, _algorithm, _publicKey.RawPublicKey);
        }

        public override string ToString()
        {
            return (ushort)_flags + " " + _protocol + " " + (byte)_algorithm + " " + Convert.ToBase64String(_publicKey.RawPublicKey);
        }

        #endregion

        #region properties

        public DnsDnsKeyFlag Flags
        { get { return _flags; } }

        public byte Protocol
        { get { return _protocol; } }

        public DnssecAlgorithm Algorithm
        { get { return _algorithm; } }

        public DnssecPublicKey PublicKey
        { get { return _publicKey; } }

        [IgnoreDataMember]
        public ushort ComputedKeyTag
        { get { return _computedKeyTag; } }

        [IgnoreDataMember]
        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(_rData.Length); } }

        #endregion
    }

    public class DnssecPublicKey
    {
        #region variables

        protected byte[] _rawPublicKey;

        #endregion

        #region constructor

        protected DnssecPublicKey()
        { }

        protected DnssecPublicKey(byte[] rawPublicKey)
        {
            _rawPublicKey = rawPublicKey;
        }

        #endregion

        #region static

        public static DnssecPublicKey Parse(DnssecAlgorithm algorithm, byte[] rawPublicKey)
        {
            switch (algorithm)
            {
                case DnssecAlgorithm.RSAMD5:
                case DnssecAlgorithm.RSASHA1:
                case DnssecAlgorithm.RSASHA256:
                case DnssecAlgorithm.RSASHA512:
                case DnssecAlgorithm.RSASHA1_NSEC3_SHA1:
                    return new DnssecRsaPublicKey(rawPublicKey);

                case DnssecAlgorithm.ECDSAP256SHA256:
                case DnssecAlgorithm.ECDSAP384SHA384:
                    return new DnssecEcdsaPublicKey(rawPublicKey, algorithm);

                default:
                    return new DnssecPublicKey(rawPublicKey);
            }
        }

        #endregion

        #region public

        public virtual bool IsSignatureValid(Stream data, byte[] signature, HashAlgorithmName hashAlgorithm)
        {
            throw new NotSupportedException("DNSSEC algorithm is not supported.");
        }

        public void WriteTo(Stream s)
        {
            s.Write(_rawPublicKey);
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnssecPublicKey other)
                return BinaryNumber.Equals(_rawPublicKey, other._rawPublicKey);

            return false;
        }

        public override int GetHashCode()
        {
            return _rawPublicKey.GetHashCode();
        }

        public override string ToString()
        {
            return Convert.ToBase64String(_rawPublicKey);
        }

        #endregion

        #region properties

        public byte[] RawPublicKey
        { get { return _rawPublicKey; } }

        [IgnoreDataMember]
        public virtual bool IsAlgorithmSupported
        { get { return false; } }

        #endregion
    }

    public class DnssecRsaPublicKey : DnssecPublicKey
    {
        #region variables

        readonly RSAParameters _rsaPublicKey;

        #endregion

        #region constructors

        public DnssecRsaPublicKey(RSAParameters rsaPublicKey)
        {
            _rsaPublicKey = rsaPublicKey;

            if (_rsaPublicKey.Exponent.Length < 256)
            {
                _rawPublicKey = new byte[1 + _rsaPublicKey.Exponent.Length + _rsaPublicKey.Modulus.Length];
                _rawPublicKey[0] = (byte)_rsaPublicKey.Exponent.Length;
                Buffer.BlockCopy(_rsaPublicKey.Exponent, 0, _rawPublicKey, 1, _rsaPublicKey.Exponent.Length);
                Buffer.BlockCopy(_rsaPublicKey.Modulus, 0, _rawPublicKey, 1 + _rsaPublicKey.Exponent.Length, _rsaPublicKey.Modulus.Length);
            }
            else
            {
                byte[] bufferExponentLength = BitConverter.GetBytes(Convert.ToUInt16(_rsaPublicKey.Exponent.Length));
                Array.Reverse(bufferExponentLength);

                _rawPublicKey = new byte[3 + _rsaPublicKey.Exponent.Length + _rsaPublicKey.Modulus.Length];
                Buffer.BlockCopy(bufferExponentLength, 0, _rawPublicKey, 1, 2);
                Buffer.BlockCopy(_rsaPublicKey.Exponent, 0, _rawPublicKey, 3, _rsaPublicKey.Exponent.Length);
                Buffer.BlockCopy(_rsaPublicKey.Modulus, 0, _rawPublicKey, 3 + _rsaPublicKey.Exponent.Length, _rsaPublicKey.Modulus.Length);
            }
        }

        public DnssecRsaPublicKey(byte[] rawPublicKey)
            : base(rawPublicKey)
        {
            if (_rawPublicKey[0] == 0)
            {
                byte[] bufferExponentLength = new byte[2];
                Buffer.BlockCopy(_rawPublicKey, 1, bufferExponentLength, 0, 2);
                Array.Reverse(bufferExponentLength);

                int exponentLength = BitConverter.ToUInt16(bufferExponentLength, 0);
                int modulusLength = _rawPublicKey.Length - exponentLength - 3;

                _rsaPublicKey.Exponent = new byte[exponentLength];
                _rsaPublicKey.Modulus = new byte[modulusLength];

                Buffer.BlockCopy(_rawPublicKey, 3, _rsaPublicKey.Exponent, 0, exponentLength);
                Buffer.BlockCopy(_rawPublicKey, 3 + exponentLength, _rsaPublicKey.Modulus, 0, modulusLength);
            }
            else
            {
                int exponentLength = _rawPublicKey[0];
                int modulusLength = _rawPublicKey.Length - exponentLength - 1;

                _rsaPublicKey.Exponent = new byte[exponentLength];
                _rsaPublicKey.Modulus = new byte[modulusLength];

                Buffer.BlockCopy(_rawPublicKey, 1, _rsaPublicKey.Exponent, 0, exponentLength);
                Buffer.BlockCopy(_rawPublicKey, 1 + exponentLength, _rsaPublicKey.Modulus, 0, modulusLength);
            }
        }

        #endregion

        #region public

        public override bool IsSignatureValid(Stream data, byte[] signature, HashAlgorithmName hashAlgorithm)
        {
            using (RSA rsa = RSA.Create(_rsaPublicKey))
            {
                return rsa.VerifyData(data, signature, hashAlgorithm, RSASignaturePadding.Pkcs1);
            }
        }

        public override string ToString()
        {
            return Convert.ToBase64String(_rsaPublicKey.Exponent) + " " + Convert.ToBase64String(_rsaPublicKey.Modulus);
        }

        #endregion

        #region properties

        public RSAParameters RsaPublicKey
        { get { return _rsaPublicKey; } }

        [IgnoreDataMember]
        public override bool IsAlgorithmSupported
        { get { return true; } }

        #endregion
    }

    public class DnssecEcdsaPublicKey : DnssecPublicKey
    {
        #region variables

        readonly ECParameters _ecdsaPublicKey;

        #endregion

        #region constructors

        public DnssecEcdsaPublicKey(ECParameters ecdsaPublicKey)
        {
            _ecdsaPublicKey = ecdsaPublicKey;

            if (_ecdsaPublicKey.Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value)
            {
                _rawPublicKey = new byte[64];

                Buffer.BlockCopy(_ecdsaPublicKey.Q.X, 0, _rawPublicKey, 0, 32);
                Buffer.BlockCopy(_ecdsaPublicKey.Q.Y, 0, _rawPublicKey, 32, 32);
            }
            else if (_ecdsaPublicKey.Curve.Oid.Value == ECCurve.NamedCurves.nistP384.Oid.Value)
            {
                _rawPublicKey = new byte[96];

                Buffer.BlockCopy(_ecdsaPublicKey.Q.X, 0, _rawPublicKey, 0, 48);
                Buffer.BlockCopy(_ecdsaPublicKey.Q.Y, 0, _rawPublicKey, 48, 48);
            }
            else
            {
                throw new NotSupportedException("ECDSA algorithm is not supported: " + _ecdsaPublicKey.Curve.Oid.FriendlyName);
            }
        }

        public DnssecEcdsaPublicKey(byte[] rawPublicKey, DnssecAlgorithm algorithm)
            : base(rawPublicKey)
        {
            switch (algorithm)
            {
                case DnssecAlgorithm.ECDSAP256SHA256:
                    {
                        byte[] x = new byte[32];
                        byte[] y = new byte[32];

                        Buffer.BlockCopy(rawPublicKey, 0, x, 0, 32);
                        Buffer.BlockCopy(rawPublicKey, 32, y, 0, 32);

                        _ecdsaPublicKey.Curve = ECCurve.NamedCurves.nistP256;
                        _ecdsaPublicKey.Q = new ECPoint() { X = x, Y = y };
                    }
                    break;

                case DnssecAlgorithm.ECDSAP384SHA384:
                    {
                        byte[] x = new byte[48];
                        byte[] y = new byte[48];

                        Buffer.BlockCopy(rawPublicKey, 0, x, 0, 48);
                        Buffer.BlockCopy(rawPublicKey, 48, y, 0, 48);

                        _ecdsaPublicKey.Curve = ECCurve.NamedCurves.nistP384;
                        _ecdsaPublicKey.Q = new ECPoint() { X = x, Y = y };
                    }
                    break;

                default:
                    throw new NotSupportedException();
            }
        }

        #endregion

        #region public

        public override bool IsSignatureValid(Stream data, byte[] signature, HashAlgorithmName hashAlgorithm)
        {
            using (ECDsa ecdsa = ECDsa.Create(_ecdsaPublicKey))
            {
                return ecdsa.VerifyData(data, signature, hashAlgorithm, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
        }

        #endregion

        #region properties

        public ECParameters EcdsaPublicKey
        { get { return _ecdsaPublicKey; } }

        [IgnoreDataMember]
        public override bool IsAlgorithmSupported
        { get { return true; } }

        #endregion
    }
}
