/*
Technitium Library
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public enum DnssecProofOfNonExistence
    {
        NoProof = 0,
        NxDomain = 1,
        NoData = 2,
        RecordSetExists = 3,
        OptOut = 4,
        InsecureDelegation = 5
    }

    //Authenticated Denial of Existence in the DNS 
    //https://datatracker.ietf.org/doc/html/rfc7129

    //Clarifications and Implementation Notes for DNS Security (DNSSEC)
    //https://datatracker.ietf.org/doc/html/rfc6840

    public class DnsNSECRecordData : DnsResourceRecordData
    {
        #region variables

        string _nextDomainName;
        IReadOnlyList<DnsResourceRecordType> _types;

        bool _isInsecureDelegation;
        bool _isAncestorDelegation;
        bool _isAncestorDNAME;

        byte[] _rData;

        #endregion

        #region constructor

        public DnsNSECRecordData(string nextDomainName, IReadOnlyList<DnsResourceRecordType> types)
        {
            _nextDomainName = nextDomainName;
            _types = types;

            Serialize();
            CheckForDelegation();
        }

        public DnsNSECRecordData(Stream s)
            : base(s)
        { }

        public DnsNSECRecordData(JsonElement jsonResourceRecord)
        {
            string rdata = jsonResourceRecord.GetProperty("data").GetString();

            _rdLength = Convert.ToUInt16(rdata.Length);

            string[] parts = rdata.TrimEnd(' ').Split(' ');

            _nextDomainName = parts[0].TrimEnd('.');

            DnsResourceRecordType[] types = new DnsResourceRecordType[parts.Length - 1];

            for (int i = 0; i < types.Length; i++)
                types[i] = Enum.Parse<DnsResourceRecordType>(parts[i + 1], true);

            _types = types;

            Serialize();
            CheckForDelegation();
        }

        #endregion

        #region static

        public static string GetWildcardFor(DnsResourceRecord nsecRecord, string nxDomain)
        {
            DnsNSECRecordData nsec = nsecRecord.RDATA as DnsNSECRecordData;

            string w1 = GetWildcardFor(nsecRecord.Name, nxDomain);
            string w2 = GetWildcardFor(nsec._nextDomainName, nxDomain);

            byte wc1 = DnsRRSIGRecordData.GetLabelCount(w1);
            byte wc2 = DnsRRSIGRecordData.GetLabelCount(w2);

            if (wc1 > wc2)
                return w1;

            return w2;
        }

        public static bool IsDomainCovered(string ownerName, string nextDomainName, string domain)
        {
            int x = CanonicalComparison(ownerName, domain);
            int y = CanonicalComparison(nextDomainName, domain);
            int z = CanonicalComparison(ownerName, nextDomainName);

            if (z < 0)
                return (x < 0) && (y > 0);
            else
                return ((x < 0) && (y < 0)) || ((x > 0) && (y > 0)); //last NSEC
        }

        public static int CanonicalComparison(string domain1, string domain2)
        {
            string[] labels1 = domain1.ToLowerInvariant().Split('.');
            string[] labels2 = domain2.ToLowerInvariant().Split('.');

            int minLength = labels1.Length;

            if (labels2.Length < minLength)
                minLength = labels2.Length;

            for (int i = 0; i < minLength; i++)
            {
                int value = CanonicalComparison(Encoding.ASCII.GetBytes(labels1[labels1.Length - 1 - i]), Encoding.ASCII.GetBytes(labels2[labels2.Length - 1 - i]));
                if (value != 0)
                    return value;
            }

            if (labels1.Length < labels2.Length)
                return -1;

            if (labels1.Length > labels2.Length)
                return 1;

            return 0;
        }

        public static int CanonicalComparison(byte[] x, byte[] y)
        {
            int minLength = x.Length;

            if (y.Length < minLength)
                minLength = y.Length;

            for (int i = 0; i < minLength; i++)
            {
                if (x[i] < y[i])
                    return -1;

                if (x[i] > y[i])
                    return 1;
            }

            if (x.Length < y.Length)
                return -1;

            if (x.Length > y.Length)
                return 1;

            return 0;
        }

        #endregion

        #region private

        internal static DnssecProofOfNonExistence GetValidatedProofOfNonExistence(IReadOnlyList<DnsResourceRecord> nsecRecords, string domain, DnsResourceRecordType type, bool wildcardAnswerValidation)
        {
            bool foundProofOfCover = false;
            string wildcardDomain = null;

            foreach (DnsResourceRecord nsecRecord in nsecRecords)
            {
                if (nsecRecord.Type != DnsResourceRecordType.NSEC)
                    continue;

                DnsNSECRecordData nsec = nsecRecord.RDATA as DnsNSECRecordData;

                if (nsecRecord.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                {
                    //found proof of existence

                    //check if the NSEC is an "ancestor delegation"
                    if ((type != DnsResourceRecordType.DS) && nsec._isAncestorDelegation)
                        continue; //cannot prove with ancestor delegation NSEC; try next NSEC

                    return nsec.GetProofOfNonExistenceFromRecordTypes(type);
                }
                else if (IsDomainCovered(nsecRecord.Name, nsec._nextDomainName, domain))
                {
                    //found proof of cover

                    if (nsec._nextDomainName.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
                        return DnssecProofOfNonExistence.NoData; //domain is empty non-terminal (ENT) so proves NO DATA

                    if (nsec._isAncestorDNAME)
                        return DnssecProofOfNonExistence.NoProof; //An NSEC or NSEC3 RR with the DNAME bit set MUST NOT be used to assume the nonexistence of any subdomain of that NSEC/NSEC3 RR's (original) owner name.

                    if (wildcardAnswerValidation)
                        return DnssecProofOfNonExistence.NxDomain; //since wildcard was already validated; the domain does not exists

                    foundProofOfCover = true;
                    wildcardDomain = GetWildcardFor(nsecRecord, domain);
                    break;
                }
            }

            if (!foundProofOfCover)
                return DnssecProofOfNonExistence.NoProof;

            //found proof of cover; so the domain does not exists but there could be a possibility of wildcard that may exist which also needs to be proved as non-existent

            //find proof for wildcard NXDomain
            foreach (DnsResourceRecord nsecRecord in nsecRecords)
            {
                if (nsecRecord.Type != DnsResourceRecordType.NSEC)
                    continue;

                DnsNSECRecordData nsec = nsecRecord.RDATA as DnsNSECRecordData;

                if (nsecRecord.Name.Equals(wildcardDomain, StringComparison.OrdinalIgnoreCase))
                {
                    //found proof of existence for a wildcard domain

                    //check if the NSEC is an "ancestor delegation"
                    if ((type != DnsResourceRecordType.DS) && nsec._isAncestorDelegation)
                        continue; //cannot prove with ancestor delegation NSEC; try next NSEC

                    //wildcard domain exists; find if record set exists or no data
                    return nsec.GetProofOfNonExistenceFromRecordTypes(type);
                }
                else if (IsDomainCovered(nsecRecord.Name, nsec._nextDomainName, wildcardDomain))
                {
                    //found proof of cover for wildcard domain

                    if (nsec._isAncestorDNAME)
                        return DnssecProofOfNonExistence.NoProof; //An NSEC or NSEC3 RR with the DNAME bit set MUST NOT be used to assume the nonexistence of any subdomain of that NSEC/NSEC3 RR's (original) owner name.

                    //proved that the actual domain does not exists since a wildcard does not exists
                    return DnssecProofOfNonExistence.NxDomain;
                }
            }

            //found no proof
            return DnssecProofOfNonExistence.NoProof;
        }

        private DnssecProofOfNonExistence GetProofOfNonExistenceFromRecordTypes(DnsResourceRecordType checkType)
        {
            if ((checkType == DnsResourceRecordType.DS) && _isInsecureDelegation)
                return DnssecProofOfNonExistence.InsecureDelegation;

            //find if record set exists
            foreach (DnsResourceRecordType type in _types)
            {
                if ((type == checkType) || (type == DnsResourceRecordType.CNAME))
                    return DnssecProofOfNonExistence.RecordSetExists;
            }

            //found no record set
            return DnssecProofOfNonExistence.NoData;
        }

        private static string GetWildcardFor(string nsecOwnerName, string nxDomain)
        {
            // abc.xyz.example.com
            // x.y.z.example.com
            // *.example.com
            string[] labels1 = nsecOwnerName.Split('.');
            string[] labels2 = nxDomain.Split('.');

            int minCount;

            if (labels1.Length < labels2.Length)
                minCount = labels1.Length;
            else
                minCount = labels2.Length;

            string wildcard = null;

            for (int i = 0; i < minCount; i++)
            {
                string label1 = labels1[labels1.Length - 1 - i];
                string label2 = labels2[labels2.Length - 1 - i];

                if (label1.Equals(label2, StringComparison.OrdinalIgnoreCase))
                {
                    if (wildcard is null)
                        wildcard = label1;
                    else
                        wildcard = label1 + "." + wildcard;
                }
            }

            if (wildcard is null)
                wildcard = "*";
            else
                wildcard = "*." + wildcard;

            return wildcard;
        }

        internal static IReadOnlyList<DnsResourceRecordType> ReadTypeBitMapsFrom(Stream s, int length)
        {
            List<DnsResourceRecordType> types = new List<DnsResourceRecordType>();
            int bytesRead = 0;

            while (bytesRead < length)
            {
                int windowBlockNumber = s.ReadByte();
                if (windowBlockNumber < 0)
                    throw new EndOfStreamException();

                int bitmapLength = s.ReadByte();
                if (bitmapLength < 0)
                    throw new EndOfStreamException();

                byte[] bitmap = s.ReadBytes(bitmapLength);

                windowBlockNumber <<= 8;

                for (int i = 0; i < bitmapLength; i++)
                {
                    int currentByte = bitmap[i];
                    int currentPosition = i * 8;

                    for (int count = 0, bitMask = 0x80; count < 8; count++, bitMask >>= 1)
                    {
                        if ((currentByte & bitMask) > 0)
                            types.Add((DnsResourceRecordType)(windowBlockNumber | (currentPosition + count)));
                    }
                }

                bytesRead += 1 + 1 + bitmapLength;
            }

            return types;
        }

        internal static void WriteTypeBitMapsTo(IReadOnlyList<DnsResourceRecordType> types, Stream s)
        {
            byte[] windowBlockSurvey = new byte[256];

            foreach (DnsResourceRecordType type in types)
            {
                int value = (int)type;
                int windowBlockNumber = value >> 8;
                byte bitNumber = (byte)(value & 0xff);

                if (windowBlockSurvey[windowBlockNumber] < bitNumber)
                    windowBlockSurvey[windowBlockNumber] = bitNumber;
            }

            for (int currentWindowBlockNumber = 0; currentWindowBlockNumber < windowBlockSurvey.Length; currentWindowBlockNumber++)
            {
                int maxBits = windowBlockSurvey[currentWindowBlockNumber];
                if (maxBits > 0)
                {
                    int bitmapLength = (int)Math.Ceiling((maxBits + 1) / 8.0);
                    byte[] bitmap = new byte[bitmapLength];

                    foreach (DnsResourceRecordType type in types)
                    {
                        int value = (int)type;
                        int windowBlockNumber = value >> 8;

                        if (windowBlockNumber == currentWindowBlockNumber)
                        {
                            byte bitNumber = (byte)(value & 0xff);
                            int i = bitNumber / 8;
                            byte count = (byte)(0x80 >> (bitNumber % 8));

                            bitmap[i] |= count;
                        }
                    }

                    s.WriteByte((byte)currentWindowBlockNumber);
                    s.WriteByte((byte)bitmapLength);
                    s.Write(bitmap, 0, bitmapLength);
                }
            }
        }

        private void Serialize()
        {
            using (MemoryStream mS = new MemoryStream())
            {
                DnsDatagram.SerializeDomainName(_nextDomainName, mS); //RFC6840: DNS names in the RDATA section of NSEC resource records are not converted to lowercase
                WriteTypeBitMapsTo(_types, mS);

                _rData = mS.ToArray();
            }
        }

        private void CheckForDelegation()
        {
            bool foundDS = false;
            bool foundSOA = false;
            bool foundNS = false;
            bool foundDNAME = false;

            foreach (DnsResourceRecordType type in _types)
            {
                switch (type)
                {
                    case DnsResourceRecordType.DS:
                        foundDS = true;
                        break;

                    case DnsResourceRecordType.SOA:
                        foundSOA = true;
                        break;

                    case DnsResourceRecordType.NS:
                        foundNS = true;
                        break;

                    case DnsResourceRecordType.DNAME:
                        foundDNAME = true;
                        break;
                }
            }

            _isInsecureDelegation = !foundDS && !foundSOA && foundNS;
            _isAncestorDelegation = foundNS && !foundSOA;
            _isAncestorDNAME = foundDNAME;
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _rData = s.ReadBytes(_rdLength);

            using (MemoryStream mS = new MemoryStream(_rData))
            {
                _nextDomainName = DnsDatagram.DeserializeDomainName(mS);
                _types = ReadTypeBitMapsFrom(mS, _rdLength - DnsDatagram.GetSerializeDomainNameLength(_nextDomainName));
            }

            CheckForDelegation();
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            s.Write(_rData);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsNSECRecordData other)
            {
                if (!_nextDomainName.Equals(other._nextDomainName, StringComparison.OrdinalIgnoreCase))
                    return false;

                if (_types.Count != other._types.Count)
                    return false;

                for (int i = 0; i < _types.Count; i++)
                {
                    if (_types[i] != other._types[i])
                        return false;
                }

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_nextDomainName, _types);
        }

        public override string ToString()
        {
            string str = _nextDomainName + ".";

            foreach (DnsResourceRecordType type in _types)
                str += " " + type.ToString();

            return str;
        }

        #endregion

        #region properties

        public string NextDomainName
        { get { return _nextDomainName; } }

        public IReadOnlyList<DnsResourceRecordType> Types
        { get { return _types; } }

        [JsonIgnore]
        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(_rData.Length); } }

        #endregion
    }
}
