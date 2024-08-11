/*
Technitium Library
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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
using System.Text.Json;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public enum DnsResourceRecordType : ushort
    {
        Unknown = 0,
        A = 1,
        NS = 2,
        MD = 3,
        MF = 4,
        CNAME = 5,
        SOA = 6,
        MB = 7,
        MG = 8,
        MR = 9,
        NULL = 10,
        WKS = 11,
        PTR = 12,
        HINFO = 13,
        MINFO = 14,
        MX = 15,
        TXT = 16,
        RP = 17,
        AFSDB = 18,
        X25 = 19,
        ISDN = 20,
        RT = 21,
        NSAP = 22,
        NSAP_PTR = 23,
        SIG = 24,
        KEY = 25,
        PX = 26,
        GPOS = 27,
        AAAA = 28,
        LOC = 29,
        NXT = 30,
        EID = 31,
        NIMLOC = 32,
        SRV = 33,
        ATMA = 34,
        NAPTR = 35,
        KX = 36,
        CERT = 37,
        A6 = 38,
        DNAME = 39,
        SINK = 40,
        OPT = 41,
        APL = 42,
        DS = 43,
        SSHFP = 44,
        IPSECKEY = 45,
        RRSIG = 46,
        NSEC = 47,
        DNSKEY = 48,
        DHCID = 49,
        NSEC3 = 50,
        NSEC3PARAM = 51,
        TLSA = 52,
        SMIMEA = 53,
        HIP = 55,
        NINFO = 56,
        RKEY = 57,
        TALINK = 58,
        CDS = 59,
        CDNSKEY = 60,
        OPENPGPKEY = 61,
        CSYNC = 62,
        ZONEMD = 63,
        SVCB = 64,
        HTTPS = 65,
        SPF = 99,
        UINFO = 100,
        UID = 101,
        GID = 102,
        UNSPEC = 103,
        NID = 104,
        L32 = 105,
        L64 = 106,
        LP = 107,
        EUI48 = 108,
        EUI64 = 109,
        TKEY = 249,
        TSIG = 250,
        IXFR = 251,
        AXFR = 252,
        MAILB = 253,
        MAILA = 254,
        ANY = 255,
        URI = 256,
        CAA = 257,
        AVC = 258,
        DOA = 259,
        AMTRELAY = 260,
        RESINFO = 261,
        WALLET = 262,
        TA = 32768,
        DLV = 32769,
        ANAME = 65280, //private use - draft-ietf-dnsop-aname-04
        FWD = 65281, //private use - conditional forwarder
        APP = 65282, //private use - application
        ALIAS = 65357 //private use - SimpleDNS ALIAS
    }

    public enum DnsClass : ushort
    {
        Unknown = 0,
        IN = 1, //the Internet
        CS = 2, //the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
        CH = 3, //the CHAOS class
        HS = 4, //Hesiod

        NONE = 254,
        ANY = 255
    }

    public enum DnssecStatus : byte
    {
        Unknown = 0,
        Disabled = 1,
        Secure = 2,
        Insecure = 3,
        Bogus = 4,
        Indeterminate = 5
    }

    public sealed class DnsResourceRecord : IComparable<DnsResourceRecord>
    {
        #region variables

        string _name;
        DnsResourceRecordType _type;
        DnsClass _class;
        uint _ttl;
        DnsResourceRecordData _rData;

        readonly int _datagramOffset;

        bool _setExpiry;
        bool _wasExpiryReset;
        DateTime _ttlExpires;
        DateTime _serveStaleTtlExpires;
        uint _serveStaleAnswerTtl;
        DnssecStatus _dnssecStatus;

        #endregion

        #region constructor

        private DnsResourceRecord()
        { }

        public DnsResourceRecord(string name, DnsResourceRecordType type, DnsClass @class, uint ttl, DnsResourceRecordData rData)
        {
            if (DnsClient.IsDomainNameUnicode(name))
                name = DnsClient.ConvertDomainNameToAscii(name);

            DnsClient.IsDomainNameValid(name, true);

            _name = name;
            _type = type;
            _class = @class;
            _ttl = ttl;
            _rData = rData;
        }

        public DnsResourceRecord(Stream s)
        {
            _datagramOffset = Convert.ToInt32(s.Position);

            _name = DnsDatagram.DeserializeDomainName(s);
            _type = (DnsResourceRecordType)DnsDatagram.ReadUInt16NetworkOrder(s);
            _class = (DnsClass)DnsDatagram.ReadUInt16NetworkOrder(s);
            _ttl = DnsDatagram.ReadUInt32NetworkOrder(s);
            _rData = ReadRecordDataFrom(s, _type);
        }

        #endregion

        #region static

        public static DnsResourceRecord ReadCacheRecordFrom(BinaryReader bR, Action<DnsResourceRecord> readTagInfo)
        {
            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                    DnsResourceRecord record = new DnsResourceRecord();

                    record._name = bR.ReadString();
                    record._type = (DnsResourceRecordType)bR.ReadUInt16();
                    record._class = (DnsClass)bR.ReadUInt16();
                    record._ttl = bR.ReadUInt32();

                    if (bR.ReadBoolean())
                        record._rData = DnsCache.DnsSpecialCacheRecordData.ReadCacheRecordFrom(bR, readTagInfo);
                    else
                        record._rData = ReadRecordDataFrom(bR.BaseStream, record._type);

                    record._setExpiry = bR.ReadBoolean();
                    record._wasExpiryReset = bR.ReadBoolean();
                    record._ttlExpires = DateTime.UnixEpoch.AddSeconds(bR.ReadInt64());
                    record._serveStaleTtlExpires = DateTime.UnixEpoch.AddSeconds(bR.ReadInt64());
                    record._dnssecStatus = (DnssecStatus)bR.ReadByte();

                    readTagInfo(record);

                    return record;

                default:
                    throw new InvalidDataException("DnsResorceRecord cache format version not supported.");
            }
        }

        public static Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> GroupRecords(IReadOnlyCollection<DnsResourceRecord> records, bool deduplicate = false)
        {
            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByDomainRecords = new Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>>();

            foreach (DnsResourceRecord record in records)
            {
                string recordName = record.Name.ToLowerInvariant();

                if (!groupedByDomainRecords.TryGetValue(recordName, out Dictionary<DnsResourceRecordType, List<DnsResourceRecord>> groupedByTypeRecords))
                {
                    groupedByTypeRecords = new Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>();
                    groupedByDomainRecords.Add(recordName, groupedByTypeRecords);
                }

                if (!groupedByTypeRecords.TryGetValue(record.Type, out List<DnsResourceRecord> groupedRecords))
                {
                    groupedRecords = new List<DnsResourceRecord>();
                    groupedByTypeRecords.Add(record.Type, groupedRecords);
                }

                if (deduplicate)
                {
                    if (!groupedRecords.Contains(record))
                        groupedRecords.Add(record);
                }
                else
                {
                    groupedRecords.Add(record);
                }
            }

            return groupedByDomainRecords;
        }

        public static bool IsRRSetExpired(IReadOnlyCollection<DnsResourceRecord> records, bool serveStale)
        {
            foreach (DnsResourceRecord record in records)
            {
                if (record.IsExpired(serveStale))
                    return true;
            }

            return false;
        }

        public static bool IsRRSetStale(IReadOnlyCollection<DnsResourceRecord> records)
        {
            foreach (DnsResourceRecord record in records)
            {
                if (record.IsStale)
                    return true;
            }

            return false;
        }

        public static DnsResourceRecordData ReadRecordDataFrom(DnsResourceRecordType type, byte[] rdata)
        {
            using MemoryStream mS = new MemoryStream(2 + rdata.Length);
            {
                DnsDatagram.WriteUInt16NetworkOrder((ushort)rdata.Length, mS);
                mS.Write(rdata);
                mS.Position = 0;

                return ReadRecordDataFrom(mS, type);
            }
        }

        #endregion

        #region private

        private static DnsResourceRecordData ReadRecordDataFrom(Stream s, DnsResourceRecordType type)
        {
            switch (type)
            {
                case DnsResourceRecordType.A:
                    return new DnsARecordData(s);

                case DnsResourceRecordType.NS:
                    return new DnsNSRecordData(s);

                case DnsResourceRecordType.CNAME:
                    return new DnsCNAMERecordData(s);

                case DnsResourceRecordType.SOA:
                    return new DnsSOARecordData(s);

                case DnsResourceRecordType.PTR:
                    return new DnsPTRRecordData(s);

                case DnsResourceRecordType.HINFO:
                    return new DnsHINFORecordData(s);

                case DnsResourceRecordType.MX:
                    return new DnsMXRecordData(s);

                case DnsResourceRecordType.TXT:
                    return new DnsTXTRecordData(s);

                case DnsResourceRecordType.RP:
                    return new DnsRPRecordData(s);

                case DnsResourceRecordType.AAAA:
                    return new DnsAAAARecordData(s);

                case DnsResourceRecordType.SRV:
                    return new DnsSRVRecordData(s);

                case DnsResourceRecordType.NAPTR:
                    return new DnsNAPTRRecordData(s);

                case DnsResourceRecordType.DNAME:
                    return new DnsDNAMERecordData(s);

                case DnsResourceRecordType.OPT:
                    return new DnsOPTRecordData(s);

                case DnsResourceRecordType.APL:
                    return new DnsAPLRecordData(s);

                case DnsResourceRecordType.DS:
                    return new DnsDSRecordData(s);

                case DnsResourceRecordType.SSHFP:
                    return new DnsSSHFPRecordData(s);

                case DnsResourceRecordType.RRSIG:
                    return new DnsRRSIGRecordData(s);

                case DnsResourceRecordType.NSEC:
                    return new DnsNSECRecordData(s);

                case DnsResourceRecordType.DNSKEY:
                    return new DnsDNSKEYRecordData(s);

                case DnsResourceRecordType.NSEC3:
                    return new DnsNSEC3RecordData(s);

                case DnsResourceRecordType.NSEC3PARAM:
                    return new DnsNSEC3PARAMRecordData(s);

                case DnsResourceRecordType.TLSA:
                    return new DnsTLSARecordData(s);

                case DnsResourceRecordType.ZONEMD:
                    return new DnsZONEMDRecordData(s);

                case DnsResourceRecordType.SVCB:
                case DnsResourceRecordType.HTTPS:
                    return new DnsSVCBRecordData(s);

                case DnsResourceRecordType.TSIG:
                    return new DnsTSIGRecordData(s);

                case DnsResourceRecordType.URI:
                    return new DnsURIRecordData(s);

                case DnsResourceRecordType.CAA:
                    return new DnsCAARecordData(s);

                case DnsResourceRecordType.ANAME:
                    return new DnsANAMERecordData(s);

                case DnsResourceRecordType.FWD:
                    return new DnsForwarderRecordData(s);

                case DnsResourceRecordType.APP:
                    return new DnsApplicationRecordData(s);

                case DnsResourceRecordType.ALIAS:
                    return new DnsALIASRecordData(s);

                default:
                    return new DnsUnknownRecordData(s);
            }
        }

        #endregion

        #region internal

        internal void NormalizeName()
        {
            _name = _name.ToLowerInvariant();
            _rData.NormalizeName();
        }

        internal void SetDnssecStatus(DnssecStatus dnssecStatus, bool force = false)
        {
            if ((_dnssecStatus == DnssecStatus.Unknown) || force)
                _dnssecStatus = dnssecStatus;
        }

        internal void FixNameForNSEC(string wildcardName)
        {
            if (_type != DnsResourceRecordType.NSEC)
                throw new InvalidOperationException();

            _name = wildcardName;
        }

        internal static string GetRelativeDomainName(string domain, string originDomain = null)
        {
            string value;

            if (string.IsNullOrEmpty(originDomain))
                value = domain + ".";
            else if (domain.Equals(originDomain, StringComparison.OrdinalIgnoreCase))
                value = "@";
            else if (domain.EndsWith("." + originDomain, StringComparison.OrdinalIgnoreCase))
                value = domain.Substring(0, domain.Length - originDomain.Length - 1);
            else
                value = domain + ".";

            return value;
        }

        #endregion

        #region public

        public void SetExpiry(uint minimumTtl, uint maximumTtl, uint serveStaleTtl, uint serveStaleAnswerTtl)
        {
            if (_ttl < minimumTtl)
                _ttl = minimumTtl; //to help keep record in cache for a minimum time
            else if (_ttl > maximumTtl)
                _ttl = maximumTtl; //to help remove record from cache early

            _setExpiry = true;
            _wasExpiryReset = false;
            _ttlExpires = DateTime.UtcNow.AddSeconds(_ttl);
            _serveStaleTtlExpires = _ttlExpires.AddSeconds(serveStaleTtl);
            _serveStaleAnswerTtl = serveStaleAnswerTtl;
        }

        public void ResetExpiry(uint seconds)
        {
            if (!_setExpiry)
                throw new InvalidOperationException("Must call SetExpiry() before ResetExpiry().");

            _wasExpiryReset = true;
            _ttlExpires = DateTime.UtcNow.AddSeconds(seconds);
        }

        public void RemoveExpiry()
        {
            _setExpiry = false;
        }

        public bool IsExpired(bool serveStale)
        {
            if (serveStale)
                return TTL < 1u;

            return IsStale;
        }

        public void WriteTo(Stream s)
        {
            WriteTo(s, null);
        }

        public void WriteTo(Stream s, List<DnsDomainOffset> domainEntries)
        {
            DnsDatagram.SerializeDomainName(_name, s, domainEntries);
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_type, s);
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_class, s);
            DnsDatagram.WriteUInt32NetworkOrder(TTL, s);

            _rData.WriteTo(s, domainEntries);
        }

        public void WriteCacheRecordTo(BinaryWriter bW, Action writeTagInfo)
        {
            bW.Write((byte)1); //version

            bW.Write(_name);
            bW.Write((ushort)_type);
            bW.Write((ushort)_class);
            bW.Write(_ttl);

            if (_rData is DnsCache.DnsSpecialCacheRecordData cacheRData)
            {
                bW.Write((byte)1);
                cacheRData.WriteCacheRecordTo(bW, writeTagInfo);
            }
            else
            {
                bW.Write((byte)0);
                _rData.WriteTo(bW.BaseStream);
            }

            bW.Write(_setExpiry);
            bW.Write(_wasExpiryReset);
            bW.Write(Convert.ToInt64((_ttlExpires - DateTime.UnixEpoch).TotalSeconds));
            bW.Write(Convert.ToInt64((_serveStaleTtlExpires - DateTime.UnixEpoch).TotalSeconds));
            bW.Write((byte)_dnssecStatus);

            writeTagInfo();
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsResourceRecord other)
            {
                if (!_name.Equals(other._name, StringComparison.OrdinalIgnoreCase))
                    return false;

                if (_type != other._type)
                    return false;

                if (_class != other._class)
                    return false;

                if (_ttl != other._ttl)
                    return false;

                return _rData.Equals(other._rData);
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_name, _type, _class, _ttl, _rData);
        }

        public int CompareTo(DnsResourceRecord other)
        {
            int value;

            value = DnsNSECRecordData.CanonicalComparison(_name, other._name);
            if (value != 0)
                return value;

            value = _type.CompareTo(other._type);
            if (value != 0)
                return value;

            return _ttl.CompareTo(other._ttl);
        }

        public override string ToString()
        {
            return ToZoneFileEntry();
        }

        public string ToZoneFileEntry(string originDomain = null)
        {
            string value = GetRelativeDomainName(_name, originDomain).PadRight(20) + "  " + _ttl.ToString().PadRight(8);

            if (Enum.IsDefined(_class))
                value += "  " + _class.ToString();
            else
                value += "  CLASS" + (ushort)_class;

            if (Enum.IsDefined(_type))
                value += "  " + _type.ToString().PadRight(12);
            else
                value += "  TYPE" + (ushort)_type;

            value += "  " + _rData.ToZoneFileEntry(originDomain);

            return value;
        }

        public void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("Name", _name);

            if (DnsClient.TryConvertDomainNameToUnicode(_name, out string nameIDN))
                jsonWriter.WriteString("NameIDN", nameIDN);

            jsonWriter.WriteString("Type", _type.ToString());
            jsonWriter.WriteString("Class", _class.ToString());
            jsonWriter.WriteString("TTL", _ttl + " (" + WebUtilities.GetFormattedTime((int)_ttl) + ")");
            jsonWriter.WriteString("RDLENGTH", _rData.RDLENGTH + " bytes");

            jsonWriter.WritePropertyName("RDATA");
            _rData.SerializeTo(jsonWriter);

            jsonWriter.WriteString("DnssecStatus", _dnssecStatus.ToString());

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        public DnsResourceRecordType Type
        { get { return _type; } }

        public DnsClass Class
        { get { return _class; } }

        public uint TTL
        {
            get
            {
                if (_setExpiry)
                {
                    DateTime utcNow = DateTime.UtcNow;

                    if (utcNow > _serveStaleTtlExpires)
                        return 0u;

                    if (utcNow > _ttlExpires)
                        return _serveStaleAnswerTtl; //stale answer TTL

                    return Convert.ToUInt32((_ttlExpires - utcNow).TotalSeconds);
                }

                return _ttl;
            }
        }

        public bool IsStale
        {
            get
            {
                if (_setExpiry)
                    return DateTime.UtcNow > _ttlExpires;

                return false;
            }
        }

        public bool WasExpiryReset
        { get { return _wasExpiryReset; } }

        public uint OriginalTtlValue
        { get { return _ttl; } }

        public DnsResourceRecordData RDATA
        { get { return _rData; } }

        public int DatagramOffset
        { get { return _datagramOffset; } }

        public int UncompressedLength
        { get { return DnsDatagram.GetSerializeDomainNameLength(_name) + 2 + 2 + 4 + 2 + _rData.UncompressedLength; } }

        public object Tag { get; set; }

        public DnssecStatus DnssecStatus
        { get { return _dnssecStatus; } }

        #endregion
    }
}
