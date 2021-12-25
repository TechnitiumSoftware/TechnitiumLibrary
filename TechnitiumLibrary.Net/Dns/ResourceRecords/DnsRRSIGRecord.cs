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
    public enum DnssecSignatureStatus
    {
        Unknown = 0,
        Valid = 1,
        Bogus = 2,
        NoDnsKey = 3
    }

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
            _rdLength = Convert.ToUInt16(jsonResourceRecord.data.Value.Length);

            string[] parts = (jsonResourceRecord.data.Value as string).Split(' ');

            _typeCovered = Enum.Parse<DnsResourceRecordType>(parts[0], true);
            _algorithm = Enum.Parse<DnssecAlgorithm>(parts[1].Replace("-", "_"), true);
            _labels = byte.Parse(parts[2]);
            _originalTtl = uint.Parse(parts[3]);
            _signatureExpiration = uint.Parse(parts[4]);
            _signatureInception = uint.Parse(parts[5]);
            _keyTag = ushort.Parse(parts[6]);
            _signersName = parts[7].TrimEnd('.');
            _signature = Convert.FromBase64String(parts[8]);
        }

        #endregion

        #region static

        public static bool IsWildcard(DnsResourceRecord rrsigRecord)
        {
            if (rrsigRecord.RDATA is DnsRRSIGRecord rrsig)
                return GetLabelCount(rrsigRecord.Name) > rrsig._labels;

            throw new InvalidOperationException();
        }

        public static bool IsWildcard(DnsResourceRecord rrsigRecord, out string nextCloserName)
        {
            if (rrsigRecord.RDATA is DnsRRSIGRecord rrsig)
            {
                if (GetLabelCount(rrsigRecord.Name) > rrsig._labels)
                {
                    nextCloserName = GetTrimmedDomain(rrsigRecord.Name, rrsig._labels + 1);
                    return true;
                }
                else
                {
                    nextCloserName = null;
                    return false;
                }
            }

            throw new InvalidOperationException();
        }

        #endregion

        #region private

        private static string GetWildcardDomain(string domain, int labelCount)
        {
            return "*." + GetTrimmedDomain(domain, labelCount);
        }

        private static string GetTrimmedDomain(string domain, int labelCount)
        {
            string[] labels = domain.Split('.');
            string nextCloserName = null;

            for (int i = 0; i < labelCount; i++)
            {
                if (nextCloserName is null)
                    nextCloserName = labels[labels.Length - 1 - i];
                else
                    nextCloserName = labels[labels.Length - 1 - i] + "." + nextCloserName;
            }

            return nextCloserName;
        }

        private static int GetLabelCount(string domain)
        {
            if (domain.Length == 0)
                return 0;

            int count = 0;

            foreach (string label in domain.Split('.'))
            {
                if (label == "*")
                    continue;

                count++;
            }

            return count;
        }

        private void Serialize()
        {
            using (MemoryStream mS = new MemoryStream(2 + 1 + 1 + 4 + 4 + 4 + 2 + DnsDatagram.GetSerializeDomainNameLength(_signersName) + _signature.Length))
            {
                WriteTo(mS, false);

                _rData = mS.ToArray();
            }
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
                Serialize();

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

        public DnssecSignatureStatus IsSignatureValid(IReadOnlyList<DnsResourceRecord> records, IReadOnlyList<DnsResourceRecord> dnsKeyRecords)
        {
            //The validator's notion of the current time MUST be less than or equal to the time listed in the RRSIG RR's Expiration field.
            if (SignatureExpiration < DateTime.UtcNow)
                return DnssecSignatureStatus.Bogus;

            //The validator's notion of the current time MUST be greater than or equal to the time listed in the RRSIG RR's Inception field.
            if (SignatureInception > DateTime.UtcNow)
                return DnssecSignatureStatus.Bogus;

            HashAlgorithmName hashAlgorithm;
            byte[] hash;

            using (MemoryStream mS = new MemoryStream(512))
            {
                //RRSIG_RDATA
                WriteTo(mS, true);

                //RR(i) = owner | type | class | TTL | RDATA length | RDATA

                string name;
                {
                    //The number of labels in the RRset owner name MUST be greater than or equal to the value in the RRSIG RR's Labels field.
                    int labelCount = GetLabelCount(records[0].Name);

                    if (_labels == labelCount)
                    {
                        //name = fqdn
                        name = records[0].Name.ToLower();
                    }
                    else if (_labels < labelCount)
                    {
                        //name = "*." | the rightmost rrsig_label labels of the fqdn
                        name = GetWildcardDomain(records[0].Name, _labels).ToLower();

                        if (_typeCovered == DnsResourceRecordType.NSEC)
                        {
                            //wildcard NSEC can be abused by an attacker to serve NXDomain or NoData responses
                            //fix NSEC record owner name to the original wildcard owner name
                            records[0].FixNameForNSEC(name);
                        }
                    }
                    else
                    {
                        //the RRSIG RR did not pass the necessary validation checks and MUST NOT be used to authenticate this RRset.
                        return DnssecSignatureStatus.Bogus;
                    }
                }

                List<SerializedResourceRecord> rrList = new List<SerializedResourceRecord>(records.Count);

                //select and serialize records
                using (MemoryStream rrBuffer = new MemoryStream(512))
                {
                    //serialize RDATA
                    foreach (DnsResourceRecord record in records)
                    {
                        byte[] firstPart;
                        byte[] rdataPart;

                        //serialize RDATA
                        record.RDATA.WriteCanonicalRecordData(rrBuffer);

                        rdataPart = rrBuffer.ToArray();
                        rrBuffer.SetLength(0);

                        //serialize owner name | type | class | Original TTL | RDATA length
                        DnsDatagram.SerializeDomainName(name, rrBuffer);
                        DnsDatagram.WriteUInt16NetworkOrder((ushort)record.Type, rrBuffer);
                        DnsDatagram.WriteUInt16NetworkOrder((ushort)record.Class, rrBuffer);
                        DnsDatagram.WriteUInt32NetworkOrder(_originalTtl, rrBuffer);
                        DnsDatagram.WriteUInt16NetworkOrder(Convert.ToUInt16(rdataPart.Length), rrBuffer);

                        firstPart = rrBuffer.ToArray();
                        rrBuffer.SetLength(0);

                        //add to list
                        rrList.Add(new SerializedResourceRecord(firstPart, rdataPart));
                    }
                }

                //Canonical RR Ordering by sorting RDATA portion of the canonical form of each RR
                rrList.Sort();

                //write sorted RR into main buffer
                foreach (SerializedResourceRecord rr in rrList)
                    rr.WriteTo(mS);

                mS.Position = 0;

                //hash
                switch (_algorithm)
                {
                    case DnssecAlgorithm.RSAMD5:
                        using (HashAlgorithm hashAlgo = MD5.Create())
                        {
                            hash = hashAlgo.ComputeHash(mS);
                        }

                        hashAlgorithm = HashAlgorithmName.MD5;
                        break;

                    case DnssecAlgorithm.DSA:
                    case DnssecAlgorithm.RSASHA1:
                    case DnssecAlgorithm.DSA_NSEC3_SHA1:
                    case DnssecAlgorithm.RSASHA1_NSEC3_SHA1:
                        using (HashAlgorithm hashAlgo = SHA1.Create())
                        {
                            hash = hashAlgo.ComputeHash(mS);
                        }

                        hashAlgorithm = HashAlgorithmName.SHA1;
                        break;

                    case DnssecAlgorithm.RSASHA256:
                    case DnssecAlgorithm.ECDSAP256SHA256:
                        using (HashAlgorithm hashAlgo = SHA256.Create())
                        {
                            hash = hashAlgo.ComputeHash(mS);
                        }

                        hashAlgorithm = HashAlgorithmName.SHA256;
                        break;

                    case DnssecAlgorithm.ECDSAP384SHA384:
                        using (HashAlgorithm hashAlgo = SHA384.Create())
                        {
                            hash = hashAlgo.ComputeHash(mS);
                        }

                        hashAlgorithm = HashAlgorithmName.SHA384;
                        break;

                    case DnssecAlgorithm.RSASHA512:
                        using (HashAlgorithm hashAlgo = SHA512.Create())
                        {
                            hash = hashAlgo.ComputeHash(mS);
                        }

                        hashAlgorithm = HashAlgorithmName.SHA512;
                        break;

                    default:
                        throw new NotSupportedException("DNSSEC hash algorithm is not supported: " + _algorithm.ToString());
                }
            }

            bool isBogus = false;

            foreach (DnsResourceRecord dnsKeyRecord in dnsKeyRecords)
            {
                if (dnsKeyRecord.Type != DnsResourceRecordType.DNSKEY)
                    continue;

                //The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST match the owner name, algorithm, and key tag for some DNSKEY RR in the zone's apex DNSKEY RRset.
                if (!dnsKeyRecord.Name.Equals(_signersName, StringComparison.OrdinalIgnoreCase))
                    continue;

                DnsDNSKEYRecord dnsKey = dnsKeyRecord.RDATA as DnsDNSKEYRecord;

                if (dnsKey.Protocol != 3)
                    continue;

                if ((dnsKey.Algorithm != _algorithm) || !dnsKey.PublicKey.IsAlgorithmSupported)
                    continue;

                if (dnsKey.ComputedKeyTag != _keyTag)
                    continue;

                //The matching DNSKEY RR MUST be present in the zone's apex DNSKEY RRset, and MUST have the Zone Flag bit (DNSKEY RDATA Flag bit 7) set.
                if (dnsKey.Flags.HasFlag(DnsDnsKeyFlag.ZoneKey))
                {
                    if (dnsKey.Flags.HasFlag(DnsDnsKeyFlag.Revoke) && (_typeCovered != DnsResourceRecordType.DNSKEY))
                        continue; //rfc5011: the resolver MUST consider this key permanently invalid for all purposes except for validating the revocation.

                    if (dnsKey.PublicKey.IsSignatureValid(hash, _signature, hashAlgorithm))
                    {
                        foreach (DnsResourceRecord validatedRecord in records)
                        {
                            if (validatedRecord.Type == _typeCovered)
                                validatedRecord.SetDnssecStatus(DnssecStatus.Secure);
                        }

                        return DnssecSignatureStatus.Valid;
                    }

                    isBogus = true;
                }
            }

            if (isBogus)
            {
                foreach (DnsResourceRecord validatedRecord in records)
                {
                    if (validatedRecord.Type == _typeCovered)
                        validatedRecord.SetDnssecStatus(DnssecStatus.Bogus);
                }

                return DnssecSignatureStatus.Bogus;
            }

            return DnssecSignatureStatus.NoDnsKey;
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

                if (!_signersName.Equals(other._signersName, StringComparison.OrdinalIgnoreCase))
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
            return (ushort)_typeCovered + " " + (byte)_algorithm + " " + _labels + " " + _originalTtl + " " + _signatureExpiration + " " + _signatureInception + " " + _keyTag + " " + _signersName + ". " + Convert.ToBase64String(_signature) + " )";
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

        class SerializedResourceRecord : IComparable<SerializedResourceRecord>
        {
            #region variables

            readonly byte[] _firstPart;
            readonly byte[] _rdataPart;

            #endregion

            #region constructor

            public SerializedResourceRecord(byte[] firstPart, byte[] rdataPart)
            {
                _firstPart = firstPart;
                _rdataPart = rdataPart;
            }

            #endregion

            #region public

            public int CompareTo(SerializedResourceRecord other)
            {
                //Canonical RR Ordering by sorting RDATA portion of the canonical form of each RR
                return DnsNSECRecord.CanonicalComparison(_rdataPart, other._rdataPart);
            }

            public void WriteTo(Stream s)
            {
                s.Write(_firstPart);
                s.Write(_rdataPart);
            }

            #endregion
        }
    }
}
