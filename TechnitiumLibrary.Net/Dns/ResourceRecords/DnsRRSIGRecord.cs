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
    public class DnsRRSIGRecord : DnsResourceRecordData
    {
        #region variables

        DnsResourceRecordType _typeCovered;
        DnssecAlgorithm _algorithm;
        byte _labels;
        uint _originalTtl;
        uint _signatureExpiration;
        uint _signatureInception;
        ushort _keyTag;
        string _signersName;
        byte[] _signature;

        byte[] _rData;

        #endregion

        #region constructors

        public DnsRRSIGRecord(DnsResourceRecordType typeCovered, DnssecAlgorithm algorithm, byte labels, uint originalTtl, uint signatureExpiration, uint signatureInception, ushort keyTag, string signersName, byte[] signature)
        {
            _typeCovered = typeCovered;
            _algorithm = algorithm;
            _labels = labels;
            _originalTtl = originalTtl;
            _signatureExpiration = signatureExpiration;
            _signatureInception = signatureInception;
            _keyTag = keyTag;
            _signersName = signersName;
            _signature = signature;
        }

        public DnsRRSIGRecord(Stream s)
            : base(s)
        { }

        public DnsRRSIGRecord(dynamic jsonResourceRecord)
        {
            throw new NotSupportedException();
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _typeCovered = (DnsResourceRecordType)DnsDatagram.ReadUInt16NetworkOrder(s);
            _algorithm = (DnssecAlgorithm)s.ReadByteValue();
            _labels = s.ReadByteValue();
            _originalTtl = DnsDatagram.ReadUInt32NetworkOrder(s);
            _signatureExpiration = DnsDatagram.ReadUInt32NetworkOrder(s);
            _signatureInception = DnsDatagram.ReadUInt32NetworkOrder(s);
            _keyTag = DnsDatagram.ReadUInt16NetworkOrder(s);
            _signersName = DnsDatagram.DeserializeDomainName(s);
            _signature = s.ReadBytes(_rdLength - 2 - 1 - 1 - 4 - 4 - 4 - 2 - DnsDatagram.GetSerializeDomainNameLength(_signersName));
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            if (_rData is null)
            {
                using (MemoryStream mS = new MemoryStream(2 + 1 + 1 + 4 + 4 + 4 + 2 + DnsDatagram.GetSerializeDomainNameLength(_signersName) + _signature.Length))
                {
                    WriteTo(mS, canonicalForm);

                    _rData = mS.ToArray();
                }
            }

            s.Write(_rData);
        }

        #endregion

        #region private

        private void WriteTo(Stream s, bool canonicalForm)
        {
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_typeCovered, s);
            s.WriteByte((byte)_algorithm);
            s.WriteByte(_labels);
            DnsDatagram.WriteUInt32NetworkOrder(_originalTtl, s);
            DnsDatagram.WriteUInt32NetworkOrder(_signatureExpiration, s);
            DnsDatagram.WriteUInt32NetworkOrder(_signatureInception, s);
            DnsDatagram.WriteUInt16NetworkOrder(_keyTag, s);
            DnsDatagram.SerializeDomainName(canonicalForm ? _signersName.ToLower() : _signersName, s);

            if (!canonicalForm)
                s.Write(_signature);
        }

        #endregion

        #region public

        public bool IsSignatureValid(IReadOnlyList<DnsResourceRecord> answer, IReadOnlyList<DnsResourceRecord> dnsKeys)
        {
            using (MemoryStream mS = new MemoryStream(512))
            {
                //RRSIG_RDATA
                WriteTo(mS, true);

                //RR(i) = owner | type | class | TTL | RDATA length | RDATA
                List<byte[]> rrBufferList = new List<byte[]>(answer.Count);

                //select and serialize records
                using (MemoryStream rrBuffer = new MemoryStream(512))
                {
                    foreach (DnsResourceRecord record in answer)
                    {
                        if (record.Type == _typeCovered)
                        {
                            record.WriteTo(rrBuffer, null, true, _originalTtl);
                            rrBufferList.Add(rrBuffer.ToArray());

                            rrBuffer.Position = 0;
                        }
                    }
                }

                //Canonical RR Ordering
                rrBufferList.Sort(DnsNSECRecord.CanonicalComparison);

                //write into main buffer
                foreach (byte[] buffer in rrBufferList)
                    mS.Write(buffer);

                //verify
                HashAlgorithmName hashAlgorithm;

                switch (_algorithm)
                {
                    case DnssecAlgorithm.RSA_MD5:
                        hashAlgorithm = HashAlgorithmName.MD5;
                        break;

                    case DnssecAlgorithm.DSA_SHA1:
                    case DnssecAlgorithm.RSA_SHA1:
                        hashAlgorithm = HashAlgorithmName.SHA1;
                        break;

                    case DnssecAlgorithm.RSA_SHA256:
                    case DnssecAlgorithm.ECDSA_P256_SHA256:
                        hashAlgorithm = HashAlgorithmName.SHA256;
                        break;

                    case DnssecAlgorithm.ECDSA_P384_SHA384:
                        hashAlgorithm = HashAlgorithmName.SHA384;
                        break;

                    case DnssecAlgorithm.RSA_SHA512:
                        hashAlgorithm = HashAlgorithmName.SHA512;
                        break;

                    default:
                        throw new NotSupportedException("Hash algorithm is not supported: " + _algorithm.ToString());
                }

                foreach (DnsResourceRecord record in dnsKeys)
                {
                    if (record.Type == DnsResourceRecordType.DNSKEY)
                    {
                        DnsDNSKEYRecord dnsKey = record.RDATA as DnsDNSKEYRecord;

                        if (dnsKey.Flags.HasFlag(DnsDnsKeyFlag.ZoneKey) && (dnsKey.Protocol == 3) && (dnsKey.ComputedKeyTag == _keyTag))
                        {
                            mS.Position = 0; //reset position before use

                            if (dnsKey.PublicKey.IsSignatureValid(mS, _signature, hashAlgorithm))
                                return true;
                        }
                    }
                }

                return false;
            }
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsRRSIGRecord other)
            {
                if (_typeCovered != other._typeCovered)
                    return false;

                if (_algorithm != other._algorithm)
                    return false;

                if (_labels != other._labels)
                    return false;

                if (_originalTtl != other._originalTtl)
                    return false;

                if (_signatureExpiration != other._signatureExpiration)
                    return false;

                if (_signatureInception != other._signatureInception)
                    return false;

                if (_keyTag != other._keyTag)
                    return false;

                if (!_signersName.Equals(other._signersName))
                    return false;

                if (!BinaryNumber.Equals(_signature, other._signature))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            HashCode hash = new HashCode();

            hash.Add(_typeCovered);
            hash.Add(_algorithm);
            hash.Add(_labels);
            hash.Add(_originalTtl);
            hash.Add(_signatureExpiration);
            hash.Add(_signatureInception);
            hash.Add(_keyTag);
            hash.Add(_signersName);
            hash.Add(_signature);

            return hash.ToHashCode();
        }

        public override string ToString()
        {
            return (ushort)_typeCovered + " " + (byte)_algorithm + " " + _labels + " " + _originalTtl + " " + _signatureExpiration + " ( " + _signatureInception + " " + _keyTag + " " + _signersName + " " + Convert.ToBase64String(_signature) + " )";
        }

        #endregion

        #region properties

        public DnsResourceRecordType TypeCovered
        { get { return _typeCovered; } }

        public DnssecAlgorithm Algorithm
        { get { return _algorithm; } }

        public byte Labels
        { get { return _labels; } }

        public uint OriginalTtl
        { get { return _originalTtl; } }

        [IgnoreDataMember]
        public uint SignatureExpirationValue
        { get { return _signatureExpiration; } }

        public DateTime SignatureExpiration
        { get { return DateTime.UnixEpoch.AddSeconds(_signatureExpiration); } }

        [IgnoreDataMember]
        public uint SignatureInceptionValue
        { get { return _signatureInception; } }

        public DateTime SignatureInception
        { get { return DateTime.UnixEpoch.AddSeconds(_signatureInception); } }

        public ushort KeyTag
        { get { return _keyTag; } }

        public string SignersName
        { get { return _signersName; } }

        public byte[] Signature
        { get { return _signature; } }

        [IgnoreDataMember]
        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(2 + 1 + 1 + 4 + 4 + 4 + 2 + DnsDatagram.GetSerializeDomainNameLength(_signersName) + _signature.Length); } }

        #endregion
    }
}
