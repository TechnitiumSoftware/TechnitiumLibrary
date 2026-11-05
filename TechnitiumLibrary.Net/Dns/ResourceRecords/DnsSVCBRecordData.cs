/*
Technitium Library
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    //Service binding and parameter specification via the DNS (DNS SVCB and HTTPS RRs)
    //https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/12/

    //Service Binding Mapping for DNS Servers
    //https://www.ietf.org/archive/id/draft-ietf-add-svcb-dns-08.html

    public enum DnsSvcParamKey : ushort
    {
        Mandatory = 0,
        ALPN = 1,
        No_Default_ALPN = 2,
        Port = 3,
        IPv4Hint = 4,
        ECH = 5,
        IPv6Hint = 6,
        DoHPath = 7,
        InvalidKey = 65535
    }

    public class DnsSVCBRecordData : DnsResourceRecordData
    {
        #region variables

        ushort _svcPriority;
        string _targetName;
        IReadOnlyDictionary<DnsSvcParamKey, DnsSvcParamValue> _svcParams;

        byte[] _rData;

        bool _autoIpv4Hint;
        bool _autoIpv6Hint;

        #endregion

        #region constructors

        public DnsSVCBRecordData(ushort svcPriority, string targetName, IReadOnlyDictionary<DnsSvcParamKey, DnsSvcParamValue> svcParams)
        {
            _svcPriority = svcPriority;
            _targetName = targetName;
            _svcParams = svcParams;
        }

        public DnsSVCBRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _rData = s.ReadExactly(_rdLength);

            using (MemoryStream mS = new MemoryStream(_rData))
            {
                _svcPriority = DnsDatagram.ReadUInt16NetworkOrder(mS);
                _targetName = DnsDatagram.DeserializeDomainName(mS);

                Dictionary<DnsSvcParamKey, DnsSvcParamValue> svcParams = new Dictionary<DnsSvcParamKey, DnsSvcParamValue>();
                ushort lastSvcParamKey = 0;
                bool hasSvcParamKey = false;

                while (mS.Position < mS.Length)
                {
                    ushort svcParamKeyWire = DnsDatagram.ReadUInt16NetworkOrder(mS);
                    if (hasSvcParamKey && (svcParamKeyWire <= lastSvcParamKey))
                        throw new DnsClientException("SVCB parameter keys are not in strictly increasing order.");

                    hasSvcParamKey = true;
                    lastSvcParamKey = svcParamKeyWire;

                    DnsSvcParamKey svcParamKey = (DnsSvcParamKey)svcParamKeyWire;
                    svcParams.Add(svcParamKey, (_svcPriority == 0) ? ReadAliasSvcParam(svcParamKey, mS) : ReadSvcParam(svcParamKey, mS));
                }

                _svcParams = svcParams;
                EnsureSvcParamsAreConsistent();
            }
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            if (_rData is null)
            {
                EnsureSvcParamsAreConsistent();

                List<KeyValuePair<DnsSvcParamKey, DnsSvcParamValue>> svcParams = new List<KeyValuePair<DnsSvcParamKey, DnsSvcParamValue>>(_svcParams);

                svcParams.Sort(delegate (KeyValuePair<DnsSvcParamKey, DnsSvcParamValue> x, KeyValuePair<DnsSvcParamKey, DnsSvcParamValue> y)
                {
                    return ((ushort)x.Key).CompareTo((ushort)y.Key);
                });

                using (MemoryStream mS = new MemoryStream(UncompressedLength))
                {
                    DnsDatagram.WriteUInt16NetworkOrder(_svcPriority, mS);
                    DnsDatagram.SerializeDomainName(canonicalForm ? DnsDatagram.ToLowerInvariantAscii(_targetName) : _targetName, mS, null); //no compression for domain name as per RFC

                    foreach (KeyValuePair<DnsSvcParamKey, DnsSvcParamValue> svcParam in svcParams)
                    {
                        DnsDatagram.WriteUInt16NetworkOrder((ushort)svcParam.Key, mS);
                        svcParam.Value.WriteTo(mS);
                    }

                    _rData = mS.ToArray();
                }
            }

            s.Write(_rData);
        }

        #endregion

        #region internal

        internal static async Task<DnsSVCBRecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsSVCBRecordData(rdata);

            ushort svcPriority = ushort.Parse(await zoneFile.PopItemAsync());
            string targetName = await zoneFile.PopDomainAsync();

            Dictionary<DnsSvcParamKey, DnsSvcParamValue> svcParams = new Dictionary<DnsSvcParamKey, DnsSvcParamValue>();
            string param;
            int i;
            DnsSvcParamKey svcParamKey;
            string svcParamValue;
            bool autoIpv4Hint = false;
            bool autoIpv6Hint = false;

            do
            {
                param = await zoneFile.PopItemAsync();
                if (param is null)
                    break;

                i = param.IndexOf('=');
                string keyToken = (i < 0) ? param : param.Substring(0, i);
                svcParamValue = (i < 0) ? "" : param.Substring(i + 1);

                if (TryParseKeyNumber(keyToken, out ushort keyNumber))
                {
                    svcParamKey = (DnsSvcParamKey)keyNumber;
                    byte[] keyValue = ZoneFile.DecodeCharacterStringOctets(svcParamValue);
                    svcParams.Add(svcParamKey, (svcPriority == 0) ? ReadAliasSvcParam(svcParamKey, keyValue) : ReadSvcParam(svcParamKey, keyValue));
                    continue;
                }

                svcParamKey = Enum.Parse<DnsSvcParamKey>(keyToken.Replace('-', '_'), true);
                svcParamValue = ZoneFile.DecodeCharacterStringToken(svcParamValue);

                switch (svcParamKey)
                {
                    case DnsSvcParamKey.IPv4Hint:
                        if (DnsDatagram.EqualsIgnoreCaseAscii(svcParamValue, "auto"))
                        {
                            autoIpv4Hint = true;
                            continue;
                        }
                        break;

                    case DnsSvcParamKey.IPv6Hint:
                        if (DnsDatagram.EqualsIgnoreCaseAscii(svcParamValue, "auto"))
                        {
                            autoIpv6Hint = true;
                            continue;
                        }
                        break;
                }

                svcParams.Add(svcParamKey, (svcPriority == 0) ? ParseAliasSvcParam(svcParamKey, svcParamValue) : DnsSvcParamValue.Parse(svcParamKey, svcParamValue));
            }
            while (true);

            DnsSVCBRecordData svcb = new DnsSVCBRecordData(svcPriority, targetName, svcParams) { _autoIpv4Hint = autoIpv4Hint, _autoIpv6Hint = autoIpv6Hint };
            svcb.EnsureSvcParamsAreConsistent();

            return svcb;
        }

        static DnsSvcParamValue ReadSvcParam(DnsSvcParamKey svcParamKey, byte[] value)
        {
            using (MemoryStream mS = new MemoryStream(2 + value.Length))
            {
                DnsDatagram.WriteUInt16NetworkOrder((ushort)value.Length, mS);
                mS.Write(value, 0, value.Length);
                mS.Position = 0;

                return ReadSvcParam(svcParamKey, mS);
            }
        }

        static DnsSvcParamValue ReadAliasSvcParam(DnsSvcParamKey svcParamKey, Stream s)
        {
            ushort length = DnsDatagram.ReadUInt16NetworkOrder(s);
            byte[] value = s.ReadExactly(length);

            return ReadAliasSvcParam(svcParamKey, value);
        }

        static DnsSvcParamValue ReadAliasSvcParam(DnsSvcParamKey svcParamKey, byte[] value)
        {
            try
            {
                return ReadSvcParam(svcParamKey, value);
            }
            catch (Exception ex) when (IsIgnoredAliasParamException(ex))
            {
                return new DnsSvcUnknownParamValue(value);
            }
        }

        static DnsSvcParamValue ParseAliasSvcParam(DnsSvcParamKey svcParamKey, string svcParamValue)
        {
            try
            {
                return DnsSvcParamValue.Parse(svcParamKey, svcParamValue);
            }
            catch (Exception ex) when (IsIgnoredAliasParamException(ex))
            {
                return new DnsSvcIgnoredParamValue(svcParamValue);
            }
        }

        static bool IsIgnoredAliasParamException(Exception ex)
        {
            return (ex is DnsClientException) || (ex is FormatException) || (ex is ArgumentException) || (ex is OverflowException) || (ex is EndOfStreamException);
        }

        static DnsSvcParamValue ReadSvcParam(DnsSvcParamKey svcParamKey, Stream s)
        {
            switch (svcParamKey)
            {
                case DnsSvcParamKey.Mandatory:
                    return new DnsSvcMandatoryParamValue(s);

                case DnsSvcParamKey.ALPN:
                    DnsSvcAlpnParamValue alpn = new DnsSvcAlpnParamValue(s);
                    if (alpn.AlpnIds.Count == 0)
                        throw new DnsClientException("SVCB alpn value must contain at least one id.");

                    return alpn;

                case DnsSvcParamKey.No_Default_ALPN:
                    DnsSvcParamValue noDefaultAlpn = new DnsSvcAlpnParamValue(s);
                    if (noDefaultAlpn.ValueLength != 0)
                        throw new DnsClientException("SVCB no-default-alpn value must be empty.");

                    return noDefaultAlpn;

                case DnsSvcParamKey.Port:
                    return new DnsSvcPortParamValue(s);

                case DnsSvcParamKey.IPv4Hint:
                    return new DnsSvcIPv4HintParamValue(s);

                case DnsSvcParamKey.IPv6Hint:
                    return new DnsSvcIPv6HintParamValue(s);

                case DnsSvcParamKey.DoHPath:
                    return new DnsSvcDoHPathParamValue(s);

                default:
                    return new DnsSvcUnknownParamValue(s);
            }
        }

        internal static DnsSvcParamKey ParseSvcParamKey(string keyToken)
        {
            if (TryParseKeyNumber(keyToken, out ushort keyNumber))
                return (DnsSvcParamKey)keyNumber;

            return Enum.Parse<DnsSvcParamKey>(keyToken.Replace('-', '_'), true);
        }

        static bool TryParseKeyNumber(string keyToken, out ushort keyNumber)
        {
            keyNumber = 0;

            if ((keyToken.Length < 4) || !keyToken.StartsWith("key", StringComparison.OrdinalIgnoreCase))
                return false;

            for (int i = 3; i < keyToken.Length; i++)
            {
                if ((keyToken[i] < '0') || (keyToken[i] > '9'))
                    return false;
            }

            if ((keyToken.Length > 4) && (keyToken[3] == '0'))
                throw new FormatException("SVCB key number must not contain leading zeros.");

            int value = 0;

            for (int i = 3; i < keyToken.Length; i++)
            {
                value = (value * 10) + (keyToken[i] - '0');
                if (value > ushort.MaxValue)
                    throw new FormatException("SVCB key number is outside the key range.");
            }

            keyNumber = (ushort)value;
            return true;
        }

        internal static string FormatSvcParamKey(DnsSvcParamKey key)
        {
            if (!Enum.IsDefined(key))
                return "key" + ((ushort)key).ToString();

            return key.ToString().ToLowerInvariant().Replace('_', '-');
        }

        static string FormatOpaqueSvcValue(byte[] value)
        {
            bool quote = false;

            foreach (byte b in value)
            {
                if ((b <= 0x20) || (b >= 0x7F) || (b == '"') || (b == '\\') || (b == '(') || (b == ')') || (b == ';'))
                {
                    quote = true;
                    break;
                }
            }

            if (!quote)
                return Encoding.ASCII.GetString(value);

            StringBuilder encoded = new StringBuilder(value.Length + 2);
            encoded.Append('"');

            foreach (byte b in value)
            {
                if ((b == (byte)'\\') || (b == (byte)'"'))
                {
                    encoded.Append('\\');
                    encoded.Append((char)b);
                }
                else if ((b < 0x20) || (b > 0x7E))
                {
                    encoded.Append('\\');
                    encoded.Append(b.ToString("D3"));
                }
                else
                {
                    encoded.Append((char)b);
                }
            }

            encoded.Append('"');
            return encoded.ToString();
        }

        internal static List<string> SplitValueList(string value)
        {
            List<string> items = new List<string>();
            StringBuilder item = new StringBuilder();

            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                if (c == '\\')
                {
                    if (i + 1 >= value.Length)
                        throw new FormatException("SVCB value-list escape is incomplete.");

                    char next = value[++i];
                    if ((next != '\\') && (next != ','))
                        throw new FormatException("SVCB value-list escape must be a comma or a backslash.");

                    item.Append(next);
                    continue;
                }

                if (c == ',')
                {
                    if (item.Length == 0)
                        throw new FormatException("SVCB value list contains an empty item.");

                    items.Add(item.ToString());
                    item.Clear();
                    continue;
                }

                item.Append(c);
            }

            if (item.Length == 0)
                throw new FormatException("SVCB value list contains an empty item.");

            items.Add(item.ToString());
            return items;
        }

        void EnsureSvcParamsAreConsistent()
        {
            if (_svcPriority == 0)
                return;

            if (_svcParams.ContainsKey(DnsSvcParamKey.No_Default_ALPN) && !_svcParams.ContainsKey(DnsSvcParamKey.ALPN))
                throw new DnsClientException("SVCB no-default-alpn requires an alpn parameter.");

            EnsureMandatoryKeysAreConsistent();
        }

        void EnsureMandatoryKeysAreConsistent()
        {
            if (!_svcParams.TryGetValue(DnsSvcParamKey.Mandatory, out DnsSvcParamValue mandatoryValue))
                return;

            if (mandatoryValue is not DnsSvcMandatoryParamValue mandatory)
                throw new DnsClientException("SVCB mandatory parameter has the wrong value type.");

            HashSet<DnsSvcParamKey> mandatoryKeys = new HashSet<DnsSvcParamKey>();

            foreach (DnsSvcParamKey key in mandatory.Keys)
            {
                if (key == DnsSvcParamKey.Mandatory)
                    throw new DnsClientException("SVCB mandatory list must not include the mandatory key.");

                if (!mandatoryKeys.Add(key))
                    throw new DnsClientException("SVCB mandatory list contains a repeated key.");

                if ((key == DnsSvcParamKey.IPv4Hint) && _autoIpv4Hint)
                    continue;

                if ((key == DnsSvcParamKey.IPv6Hint) && _autoIpv6Hint)
                    continue;

                if (!_svcParams.ContainsKey(key))
                    throw new DnsClientException("SVCB mandatory key is missing from the record.");
            }
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            EnsureSvcParamsAreConsistent();

            string svcParams = string.Empty;

            foreach (KeyValuePair<DnsSvcParamKey, DnsSvcParamValue> svcParam in _svcParams)
            {
                if ((_svcPriority == 0) && (svcParam.Value is DnsSvcUnknownParamValue aliasRaw))
                {
                    svcParams += " key" + ((ushort)svcParam.Key).ToString() + "=" + FormatOpaqueSvcValue(aliasRaw.Value);
                    continue;
                }

                if (svcParam.Value is DnsSvcIgnoredParamValue)
                {
                    svcParams += " " + FormatSvcParamKey(svcParam.Key) + "=" + DnsDatagram.EncodeCharacterString(svcParam.Value.ToString());
                    continue;
                }

                switch (svcParam.Key)
                {
                    case DnsSvcParamKey.No_Default_ALPN:
                        svcParams += " " + FormatSvcParamKey(svcParam.Key);
                        break;

                    case DnsSvcParamKey.ALPN:
                        svcParams += " " + FormatSvcParamKey(svcParam.Key) + "=" + DnsDatagram.EncodeCharacterString(svcParam.Value.ToString());
                        break;

                    case DnsSvcParamKey.DoHPath:
                        svcParams += " " + FormatSvcParamKey(svcParam.Key) + "=" + DnsDatagram.EncodeCharacterString(svcParam.Value.ToString());
                        break;

                    case DnsSvcParamKey.IPv4Hint:
                        if (_autoIpv4Hint)
                            continue;

                        svcParams += " ipv4hint=" + svcParam.Value.ToString();
                        break;

                    case DnsSvcParamKey.IPv6Hint:
                        if (_autoIpv6Hint)
                            continue;

                        svcParams += " ipv6hint=" + svcParam.Value.ToString();
                        break;

                    default:
                        if (!Enum.IsDefined(svcParam.Key) && (svcParam.Value is DnsSvcUnknownParamValue unknown))
                            svcParams += " " + FormatSvcParamKey(svcParam.Key) + "=" + FormatOpaqueSvcValue(unknown.Value);
                        else
                            svcParams += " " + FormatSvcParamKey(svcParam.Key) + "=" + svcParam.Value.ToString();

                        break;
                }
            }

            if (_autoIpv4Hint)
                svcParams += " ipv4hint=auto";

            if (_autoIpv6Hint)
                svcParams += " ipv6hint=auto";

            return _svcPriority + " " + DnsResourceRecord.GetRelativeDomainName(_targetName, originDomain) + svcParams;
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsSVCBRecordData other)
            {
                if (_svcPriority != other._svcPriority)
                    return false;

                if (!DnsDatagram.EqualsIgnoreCaseAscii(_targetName, other._targetName))
                    return false;

                if (_svcParams.Count != other._svcParams.Count)
                    return false;

                foreach (KeyValuePair<DnsSvcParamKey, DnsSvcParamValue> svcParam in _svcParams)
                {
                    if (!other._svcParams.TryGetValue(svcParam.Key, out DnsSvcParamValue otherSvcParamValue))
                        return false;

                    if (!svcParam.Value.Equals(otherSvcParamValue))
                        return false;
                }

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_svcPriority, DnsDatagram.GetHashCodeIgnoreCaseAscii(_targetName), _svcParams.GetArrayHashCode());
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteNumber("SvcPriority", _svcPriority);
            jsonWriter.WriteString("TargetName", _targetName);

            jsonWriter.WritePropertyName("SvcParams");
            jsonWriter.WriteStartObject();

            foreach (KeyValuePair<DnsSvcParamKey, DnsSvcParamValue> svcParam in _svcParams)
                jsonWriter.WriteString(svcParam.Key.ToString().ToLowerInvariant().Replace('_', '-'), svcParam.Value.ToString());

            jsonWriter.WriteEndObject();

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public ushort SvcPriority
        { get { return _svcPriority; } }

        public string TargetName
        { get { return _targetName; } }

        public IReadOnlyDictionary<DnsSvcParamKey, DnsSvcParamValue> SvcParams
        { get { return _svcParams; } }

        public bool AutoIpv4Hint
        {
            get { return _autoIpv4Hint; }
            set { _autoIpv4Hint = value; }
        }

        public bool AutoIpv6Hint
        {
            get { return _autoIpv6Hint; }
            set { _autoIpv6Hint = value; }
        }

        public override int UncompressedLength
        {
            get
            {
                int scvParamLength = 0;

                foreach (KeyValuePair<DnsSvcParamKey, DnsSvcParamValue> svcParam in _svcParams)
                    scvParamLength += 2 + 2 + svcParam.Value.UncompressedLength;

                return 2 + DnsDatagram.GetSerializeDomainNameLength(_targetName) + scvParamLength;
            }
        }

        #endregion
    }

    public abstract class DnsSvcParamValue
    {
        #region variables

        protected readonly ushort _length;

        internal ushort ValueLength
        { get { return _length; } }

        #endregion

        #region constructors

        protected DnsSvcParamValue()
        { }

        public DnsSvcParamValue(Stream s)
        {
            _length = DnsDatagram.ReadUInt16NetworkOrder(s);

            byte[] value = new byte[_length];
            s.ReadExactly(value, 0, value.Length);

            using (MemoryStream valueStream = new MemoryStream(value, writable: false))
            {
                ReadSvcParamValue(valueStream);

                if (valueStream.Position != valueStream.Length)
                    throw new DnsClientException("SVCB parameter length does not match its value.");
            }
        }

        #endregion

        #region static

        public static DnsSvcParamValue Parse(DnsSvcParamKey svcParamKey, string svcParamValue)
        {
            switch (svcParamKey)
            {
                case DnsSvcParamKey.Mandatory:
                    return DnsSvcMandatoryParamValue.Parse(svcParamValue);

                case DnsSvcParamKey.ALPN:
                    return DnsSvcAlpnParamValue.Parse(svcParamValue);

                case DnsSvcParamKey.No_Default_ALPN:
                    if (svcParamValue.Length != 0)
                        throw new FormatException("SVCB no-default-alpn value must be empty.");

                    return new DnsSvcAlpnParamValue();

                case DnsSvcParamKey.Port:
                    return DnsSvcPortParamValue.Parse(svcParamValue);

                case DnsSvcParamKey.IPv4Hint:
                    return DnsSvcIPv4HintParamValue.Parse(svcParamValue);

                case DnsSvcParamKey.IPv6Hint:
                    return DnsSvcIPv6HintParamValue.Parse(svcParamValue);

                case DnsSvcParamKey.DoHPath:
                    return new DnsSvcDoHPathParamValue(svcParamValue);

                default:
                    return DnsSvcUnknownParamValue.Parse(svcParamValue);
            }
        }

        #endregion

        #region protected

        protected abstract void ReadSvcParamValue(Stream s);

        protected abstract void WriteSvcParamValue(Stream s);

        #endregion

        #region public

        public void WriteTo(Stream s)
        {
            long originalPosition = s.Position;

            //write dummy length
            s.Position += 2;

            //write svc param value
            WriteSvcParamValue(s);

            long finalPosition = s.Position;

            //write actual length
            ushort length = Convert.ToUInt16(finalPosition - originalPosition - 2);
            s.Position = originalPosition;
            DnsDatagram.WriteUInt16NetworkOrder(length, s);

            s.Position = finalPosition;
        }

        public abstract override bool Equals(object obj);

        public abstract override int GetHashCode();

        public abstract override string ToString();

        #endregion

        #region protected

        public abstract int UncompressedLength
        { get; }

        #endregion
    }

    public class DnsSvcUnknownParamValue : DnsSvcParamValue
    {
        #region variables

        byte[] _value;

        #endregion

        #region constructors

        public DnsSvcUnknownParamValue(byte[] value)
        {
            _value = value;
        }

        public DnsSvcUnknownParamValue(Stream s)
            : base(s)
        { }

        #endregion

        #region static

        public static DnsSvcUnknownParamValue Parse(string svcParamValue)
        {
            if (svcParamValue.Contains(':'))
                return new DnsSvcUnknownParamValue(svcParamValue.ParseColonHexString());
            else
                return new DnsSvcUnknownParamValue(Convert.FromHexString(svcParamValue));
        }

        #endregion

        #region protected

        protected override void ReadSvcParamValue(Stream s)
        {
            _value = s.ReadExactly(_length);
        }

        protected override void WriteSvcParamValue(Stream s)
        {
            s.Write(_value);
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsSvcUnknownParamValue other)
                return _value.SequenceEqual(other._value);

            return false;
        }

        public override int GetHashCode()
        {
            return _value.GetArrayHashCode();
        }

        public override string ToString()
        {
            return BitConverter.ToString(_value).Replace('-', ':');
        }

        #endregion

        #region properties

        public byte[] Value
        { get { return _value; } }

        public override int UncompressedLength
        { get { return _value.Length; } }

        #endregion
    }

    class DnsSvcIgnoredParamValue : DnsSvcParamValue
    {
        #region variables

        readonly string _presentation;

        #endregion

        #region constructors

        public DnsSvcIgnoredParamValue(string presentation)
        {
            _presentation = presentation;
        }

        #endregion

        #region protected

        protected override void ReadSvcParamValue(Stream s)
        {
            s.ReadExactly(_length);
        }

        protected override void WriteSvcParamValue(Stream s)
        {
            foreach (char c in _presentation)
            {
                if (c > 0xFF)
                    throw new DnsClientException("SVCB parameter value contains a character that is not an octet.");

                s.WriteByte((byte)c);
            }
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            return (obj is DnsSvcIgnoredParamValue other) && _presentation.Equals(other._presentation, StringComparison.Ordinal);
        }

        public override int GetHashCode()
        {
            return StringComparer.Ordinal.GetHashCode(_presentation);
        }

        public override string ToString()
        {
            return _presentation;
        }

        #endregion

        #region properties

        public override int UncompressedLength
        { get { return _presentation.Length; } }

        #endregion
    }

    public class DnsSvcMandatoryParamValue : DnsSvcParamValue
    {
        #region variables

        IReadOnlyList<DnsSvcParamKey> _keys;

        #endregion

        #region constructor

        public DnsSvcMandatoryParamValue(IReadOnlyList<DnsSvcParamKey> keys)
        {
            if (keys.Count < 1)
                throw new ArgumentException("Missing param value for 'mandatory' key.");

            _keys = keys;
        }

        public DnsSvcMandatoryParamValue(Stream s)
            : base(s)
        { }

        #endregion

        #region static

        public static DnsSvcMandatoryParamValue Parse(string svcParamValue)
        {
            List<string> parts = DnsSVCBRecordData.SplitValueList(svcParamValue);
            DnsSvcParamKey[] keys = new DnsSvcParamKey[parts.Count];

            for (int i = 0; i < parts.Count; i++)
                keys[i] = DnsSVCBRecordData.ParseSvcParamKey(parts[i]);

            return new DnsSvcMandatoryParamValue(keys);
        }

        #endregion

        #region protected

        protected override void ReadSvcParamValue(Stream s)
        {
            if (_length == 0)
                throw new DnsClientException("SVCB mandatory value must list at least one key.");

            int count = _length / 2;
            DnsSvcParamKey[] keys = new DnsSvcParamKey[count];
            ushort lastKey = 0;
            bool hasKey = false;

            for (int i = 0; i < count; i++)
            {
                ushort keyWire = DnsDatagram.ReadUInt16NetworkOrder(s);
                if (keyWire == (ushort)DnsSvcParamKey.Mandatory)
                    throw new DnsClientException("SVCB mandatory list must not include the mandatory key.");

                if (hasKey && (keyWire <= lastKey))
                    throw new DnsClientException("SVCB mandatory keys are not in strictly increasing order.");

                hasKey = true;
                lastKey = keyWire;
                keys[i] = (DnsSvcParamKey)keyWire;
            }

            _keys = keys;
        }

        protected override void WriteSvcParamValue(Stream s)
        {
            List<DnsSvcParamKey> keys = new List<DnsSvcParamKey>(_keys);

            keys.Sort(delegate (DnsSvcParamKey x, DnsSvcParamKey y)
            {
                return ((ushort)x).CompareTo((ushort)y);
            });

            foreach (DnsSvcParamKey key in keys)
                DnsDatagram.WriteUInt16NetworkOrder((ushort)key, s);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsSvcMandatoryParamValue other)
            {
                if (_keys.Count != other._keys.Count)
                    return false;

                for (int i = 0; i < _keys.Count; i++)
                {
                    if (_keys[i] != other._keys[i])
                        return false;
                }

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return _keys.GetArrayHashCode();
        }

        public override string ToString()
        {
            string value = null;

            foreach (DnsSvcParamKey key in _keys)
            {
                if (value is null)
                    value = DnsSVCBRecordData.FormatSvcParamKey(key);
                else
                    value += "," + DnsSVCBRecordData.FormatSvcParamKey(key);
            }

            return value;
        }

        #endregion

        #region properties

        public IReadOnlyList<DnsSvcParamKey> Keys
        { get { return _keys; } }

        public override int UncompressedLength
        { get { return _keys.Count * 2; } }

        #endregion
    }

    public class DnsSvcAlpnParamValue : DnsSvcParamValue
    {
        #region variables

        IReadOnlyList<string> _alpnIds;

        #endregion

        #region constructor

        public DnsSvcAlpnParamValue()
        {
            _alpnIds = Array.Empty<string>();
        }

        public DnsSvcAlpnParamValue(IReadOnlyList<string> alpnIds)
        {
            if (alpnIds.Count < 1)
                throw new ArgumentException("Missing param value for 'alpn' key.");

            foreach (string alpnId in alpnIds)
            {
                if ((alpnId is null) || (alpnId.Length < 1) || (alpnId.Length > 255))
                    throw new ArgumentException("SVCB alpn id must be 1 to 255 octets.");

                foreach (char c in alpnId)
                {
                    if (c > 0xFF)
                        throw new ArgumentException("SVCB alpn id must be 1 to 255 octets.");
                }
            }

            _alpnIds = alpnIds;
        }

        public DnsSvcAlpnParamValue(Stream s)
            : base(s)
        { }

        #endregion

        #region static

        public static DnsSvcAlpnParamValue Parse(string svcParamValue)
        {
            return new DnsSvcAlpnParamValue(DnsSVCBRecordData.SplitValueList(svcParamValue));
        }

        #endregion

        #region protected

        protected override void ReadSvcParamValue(Stream s)
        {
            List<string> alpnIds = new List<string>();
            int bytesRead = 0;
            int alpnLength;

            while (bytesRead < _length)
            {
                alpnLength = s.ReadByte();
                if (alpnLength < 0)
                    throw new EndOfStreamException();

                if (alpnLength == 0)
                    throw new DnsClientException("SVCB alpn id must contain at least one octet.");

                alpnIds.Add(Encoding.Latin1.GetString(s.ReadExactly(alpnLength)));

                bytesRead += alpnLength + 1;
            }

            _alpnIds = alpnIds;
        }

        protected override void WriteSvcParamValue(Stream s)
        {
            foreach (string alpnId in _alpnIds)
            {
                s.WriteByte(Convert.ToByte(alpnId.Length));
                s.Write(Encoding.Latin1.GetBytes(alpnId));
            }
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsSvcAlpnParamValue other)
            {
                if (_alpnIds.Count != other._alpnIds.Count)
                    return false;

                for (int i = 0; i < _alpnIds.Count; i++)
                {
                    if (!_alpnIds[i].Equals(other._alpnIds[i], StringComparison.Ordinal))
                        return false;
                }

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            HashCode hash = new HashCode();

            foreach (string alpnId in _alpnIds)
                hash.Add(StringComparer.Ordinal.GetHashCode(alpnId));

            return hash.ToHashCode();
        }

        public override string ToString()
        {
            if (_alpnIds.Count == 0)
                return null;

            StringBuilder value = new StringBuilder();

            for (int i = 0; i < _alpnIds.Count; i++)
            {
                if (i > 0)
                    value.Append(',');

                foreach (char c in _alpnIds[i])
                {
                    if ((c == '\\') || (c == ','))
                        value.Append('\\');

                    value.Append(c);
                }
            }

            return value.ToString();
        }

        #endregion

        #region properties

        public IReadOnlyList<string> AlpnIds
        { get { return _alpnIds; } }

        public override int UncompressedLength
        {
            get
            {
                int length = 0;

                foreach (string alpnId in _alpnIds)
                    length += 1 + alpnId.Length;

                return length;
            }
        }

        #endregion
    }

    public class DnsSvcPortParamValue : DnsSvcParamValue
    {
        #region variables

        ushort _port;

        #endregion

        #region constructors

        public DnsSvcPortParamValue(ushort port)
        {
            _port = port;
        }

        public DnsSvcPortParamValue(Stream s)
            : base(s)
        { }

        #endregion

        #region static

        public static DnsSvcPortParamValue Parse(string svcParamValue)
        {
            if (string.IsNullOrEmpty(svcParamValue))
                throw new ArgumentException("Missing param value for 'port' key.");

            return new DnsSvcPortParamValue(ushort.Parse(svcParamValue));
        }

        #endregion

        #region protected

        protected override void ReadSvcParamValue(Stream s)
        {
            _port = DnsDatagram.ReadUInt16NetworkOrder(s);
        }

        protected override void WriteSvcParamValue(Stream s)
        {
            DnsDatagram.WriteUInt16NetworkOrder(_port, s);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsSvcPortParamValue other)
                return _port == other._port;

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_port);
        }

        public override string ToString()
        {
            return _port.ToString();
        }

        #endregion

        #region properties

        public ushort Port
        { get { return _port; } }

        public override int UncompressedLength
        { get { return 2; } }

        #endregion
    }

    public class DnsSvcIPv4HintParamValue : DnsSvcParamValue
    {
        #region variables

        IReadOnlyList<IPAddress> _addresses;

        #endregion

        #region constructors

        public DnsSvcIPv4HintParamValue(IReadOnlyList<IPAddress> addresses)
        {
            if (addresses.Count < 1)
                throw new ArgumentException("Missing param value for 'ipv4hint' key.");

            foreach (IPAddress address in addresses)
            {
                if (address.AddressFamily != AddressFamily.InterNetwork)
                    throw new ArgumentException("IPv4 hints must contain only IPv4 addresses.");
            }

            _addresses = addresses;
        }

        public DnsSvcIPv4HintParamValue(Stream s)
            : base(s)
        { }

        #endregion

        #region static

        public static DnsSvcIPv4HintParamValue Parse(string svcParamValue)
        {
            List<string> parts = DnsSVCBRecordData.SplitValueList(svcParamValue);
            IPAddress[] addresses = new IPAddress[parts.Count];

            for (int i = 0; i < parts.Count; i++)
                addresses[i] = IPAddress.Parse(parts[i]);

            return new DnsSvcIPv4HintParamValue(addresses);
        }

        #endregion

        #region protected

        protected override void ReadSvcParamValue(Stream s)
        {
            if (_length == 0)
                throw new DnsClientException("SVCB ipv4hint value must contain at least one address.");

            int count = _length / 4;
            IPAddress[] addresses = new IPAddress[count];
            Span<byte> buffer = stackalloc byte[4];

            for (int i = 0; i < count; i++)
            {
                s.ReadExactly(buffer);
                addresses[i] = new IPAddress(buffer);
            }

            _addresses = addresses;
        }

        protected override void WriteSvcParamValue(Stream s)
        {
            foreach (IPAddress address in _addresses)
                s.Write(address.GetAddressBytes());
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsSvcIPv4HintParamValue other)
            {
                if (_addresses.Count != other._addresses.Count)
                    return false;

                for (int i = 0; i < _addresses.Count; i++)
                {
                    if (!_addresses[i].Equals(other._addresses[i]))
                        return false;
                }

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return _addresses.GetArrayHashCode();
        }

        public override string ToString()
        {
            string value = null;

            foreach (IPAddress address in _addresses)
            {
                if (value is null)
                    value = address.ToString();
                else
                    value += "," + address.ToString();
            }

            return value;
        }

        #endregion

        #region properties

        public IReadOnlyList<IPAddress> Addresses
        { get { return _addresses; } }

        public override int UncompressedLength
        { get { return _addresses.Count * 4; } }

        #endregion
    }

    public class DnsSvcIPv6HintParamValue : DnsSvcParamValue
    {
        #region variables

        IReadOnlyList<IPAddress> _addresses;

        #endregion

        #region constructors

        public DnsSvcIPv6HintParamValue(IReadOnlyList<IPAddress> addresses)
        {
            if (addresses.Count < 1)
                throw new ArgumentException("Missing param value for 'ipv6hint' key.");

            foreach (IPAddress address in addresses)
            {
                if (address.AddressFamily != AddressFamily.InterNetworkV6)
                    throw new ArgumentException("IPv6 hints must contain only IPv6 addresses.");
            }

            _addresses = addresses;
        }

        public DnsSvcIPv6HintParamValue(Stream s)
            : base(s)
        { }

        #endregion

        #region static

        public static DnsSvcIPv6HintParamValue Parse(string svcParamValue)
        {
            List<string> parts = DnsSVCBRecordData.SplitValueList(svcParamValue);
            IPAddress[] addresses = new IPAddress[parts.Count];

            for (int i = 0; i < parts.Count; i++)
                addresses[i] = IPAddress.Parse(parts[i]);

            return new DnsSvcIPv6HintParamValue(addresses);
        }

        #endregion

        #region protected

        protected override void ReadSvcParamValue(Stream s)
        {
            if (_length == 0)
                throw new DnsClientException("SVCB ipv6hint value must contain at least one address.");

            int count = _length / 16;
            IPAddress[] addresses = new IPAddress[count];
            Span<byte> buffer = stackalloc byte[16];

            for (int i = 0; i < count; i++)
            {
                s.ReadExactly(buffer);
                addresses[i] = new IPAddress(buffer);
            }

            _addresses = addresses;
        }

        protected override void WriteSvcParamValue(Stream s)
        {
            foreach (IPAddress address in _addresses)
                s.Write(address.GetAddressBytes());
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsSvcIPv6HintParamValue other)
            {
                if (_addresses.Count != other._addresses.Count)
                    return false;

                for (int i = 0; i < _addresses.Count; i++)
                {
                    if (!_addresses[i].Equals(other._addresses[i]))
                        return false;
                }

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return _addresses.GetArrayHashCode();
        }

        public override string ToString()
        {
            string value = null;

            foreach (IPAddress address in _addresses)
            {
                if (value is null)
                    value = address.ToString();
                else
                    value += "," + address.ToString();
            }

            return value;
        }

        #endregion

        #region properties

        public IReadOnlyList<IPAddress> Addresses
        { get { return _addresses; } }

        public override int UncompressedLength
        { get { return _addresses.Count * 16; } }

        #endregion
    }

    public class DnsSvcDoHPathParamValue : DnsSvcParamValue
    {
        #region variables

        string _dohPath;

        #endregion

        #region constructor

        public DnsSvcDoHPathParamValue(string dohPath)
        {
            if (!dohPath.StartsWith('/'))
                throw new ArgumentException("DoH path template must be relative and start with a '/'.");

            if (!ContainsDnsVariable(dohPath))
                throw new ArgumentException("DoH path template must contain a variable named 'dns'.");

            if (!ExpandsToServicePath(dohPath))
                throw new ArgumentException("DoH path template must expand to an HTTP path that includes the 'dns' value.");

            _dohPath = dohPath;
        }

        public DnsSvcDoHPathParamValue(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadSvcParamValue(Stream s)
        {
            _dohPath = Encoding.UTF8.GetString(s.ReadExactly(_length));

            if (!_dohPath.StartsWith('/'))
                throw new DnsClientException("SVCB dohpath template must be relative and start with a '/'.");

            if (!ContainsDnsVariable(_dohPath))
                throw new DnsClientException("SVCB dohpath template must contain a variable named 'dns'.");

            if (!ExpandsToServicePath(_dohPath))
                throw new DnsClientException("SVCB dohpath template must expand to an HTTP path that includes the 'dns' value.");
        }

        static bool ExpandsToServicePath(string template)
        {
            const string sample = "AAAA";
            StringBuilder expanded = new StringBuilder();
            bool includedDns = false;

            for (int i = 0; i < template.Length; i++)
            {
                if (template[i] != '{')
                {
                    expanded.Append(template[i]);
                    continue;
                }

                int close = template.IndexOf('}', i + 1);
                if ((close < 0) || !TryExpandExpression(template, i + 1, close, sample, expanded, ref includedDns))
                    return false;

                i = close;
            }

            return includedDns && IsHttpPath(expanded.ToString());
        }

        static bool TryExpandExpression(string template, int start, int end, string sample, StringBuilder expanded, ref bool includedDns)
        {
            int i = start;
            char op = '\0';

            if ((i < end) && IsUriTemplateOperator(template[i]))
            {
                op = template[i];
                i++;
            }

            switch (op)
            {
                case '#':
                case '=':
                case ',':
                case '!':
                case '@':
                case '|':
                    return false;
            }

            List<string> names = new List<string>();
            List<string> values = new List<string>();

            while (i < end)
            {
                if (!TryReadVariableName(template, ref i, end, out string name))
                    return false;

                string value = null;
                if (name.Equals("dns", StringComparison.Ordinal))
                    value = sample;

                if ((i < end) && (template[i] == ':'))
                {
                    i++;

                    int prefix = 0;
                    int digits = 0;
                    while ((i < end) && (digits < 4) && (template[i] >= '0') && (template[i] <= '9'))
                    {
                        prefix = (prefix * 10) + (template[i] - '0');
                        i++;
                        digits++;
                    }

                    if (digits == 0)
                        return false;

                    if ((value is not null) && (prefix < value.Length))
                        value = value.Substring(0, prefix);
                }
                else if ((i < end) && (template[i] == '*'))
                {
                    i++;
                }

                names.Add(name);
                values.Add(value);

                if (i >= end)
                    break;

                if (template[i] != ',')
                    return false;

                i++;

                if (i >= end)
                    return false;
            }

            if (names.Count == 0)
                return false;

            switch (op)
            {
                case '.':
                case '/':
                    for (int n = 0; n < names.Count; n++)
                    {
                        if (values[n] is null)
                            continue;

                        expanded.Append(op);
                        expanded.Append(values[n]);
                        if ((names[n] == "dns") && (values[n].Length > 0))
                            includedDns = true;
                    }

                    break;

                case ';':
                    for (int n = 0; n < names.Count; n++)
                    {
                        if (values[n] is null)
                            continue;

                        expanded.Append(';');
                        expanded.Append(names[n]);
                        if (values[n].Length > 0)
                        {
                            expanded.Append('=');
                            expanded.Append(values[n]);
                            if (names[n] == "dns")
                                includedDns = true;
                        }
                    }

                    break;

                case '?':
                case '&':
                    bool first = true;
                    for (int n = 0; n < names.Count; n++)
                    {
                        if (values[n] is null)
                            continue;

                        expanded.Append(first ? op : '&');
                        first = false;
                        expanded.Append(names[n]);
                        if (values[n].Length > 0)
                        {
                            expanded.Append('=');
                            expanded.Append(values[n]);
                            if (names[n] == "dns")
                                includedDns = true;
                        }
                    }

                    break;

                default:
                    bool started = false;
                    for (int n = 0; n < names.Count; n++)
                    {
                        if (values[n] is null)
                            continue;

                        if (started)
                            expanded.Append(',');

                        expanded.Append(values[n]);
                        started = true;
                        if ((names[n] == "dns") && (values[n].Length > 0))
                            includedDns = true;
                    }

                    break;
            }

            return true;
        }

        static bool IsHttpPath(string value)
        {
            if ((value.Length == 0) || (value[0] != '/'))
                return false;

            int i = 1;
            if ((i < value.Length) && (value[i] != '?'))
            {
                if (!ReadPathSegment(value, ref i, true))
                    return false;

                while ((i < value.Length) && (value[i] == '/'))
                {
                    i++;
                    if (!ReadPathSegment(value, ref i, false))
                        return false;
                }
            }

            if ((i < value.Length) && (value[i] == '?'))
            {
                i++;
                while (i < value.Length)
                {
                    if ((value[i] == '/') || (value[i] == '?'))
                    {
                        i++;
                        continue;
                    }

                    if (!ReadPathChar(value, ref i))
                        return false;
                }
            }

            return i == value.Length;
        }

        static bool ReadPathSegment(string value, ref int i, bool requireOne)
        {
            int start = i;
            while (ReadPathChar(value, ref i))
            { }

            return !requireOne || (i > start);
        }

        static bool ReadPathChar(string value, ref int i)
        {
            if (i >= value.Length)
                return false;

            char c = value[i];
            if (IsPathChar(c))
            {
                i++;
                return true;
            }

            if ((c == '%') && (i + 2 < value.Length) && Uri.IsHexDigit(value[i + 1]) && Uri.IsHexDigit(value[i + 2]))
            {
                i += 3;
                return true;
            }

            return false;
        }

        static bool IsPathChar(char c)
        {
            if (((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z')) || ((c >= '0') && (c <= '9')))
                return true;

            switch (c)
            {
                case '-':
                case '.':
                case '_':
                case '~':
                case '!':
                case '$':
                case '&':
                case '\'':
                case '(':
                case ')':
                case '*':
                case '+':
                case ',':
                case ';':
                case '=':
                case ':':
                case '@':
                    return true;

                default:
                    return false;
            }
        }

        static bool ContainsDnsVariable(string template)
        {
            bool sawDns = false;

            for (int i = 0; i < template.Length; i++)
            {
                if (template[i] != '{')
                    continue;

                int close = template.IndexOf('}', i + 1);
                if (close < 0)
                    return false;

                if (!TryReadTemplateExpression(template, i + 1, close, ref sawDns))
                    return false;

                i = close;
            }

            return sawDns;
        }

        static bool TryReadTemplateExpression(string template, int start, int end, ref bool sawDns)
        {
            int i = start;

            if ((i < end) && IsUriTemplateOperator(template[i]))
                i++;

            if (i >= end)
                return false;

            while (i < end)
            {
                if (!TryReadVariableName(template, ref i, end, out string name))
                    return false;

                if (name.Equals("dns", StringComparison.Ordinal))
                    sawDns = true;

                if ((i < end) && (template[i] == ':'))
                {
                    i++;

                    int digits = 0;
                    while ((i < end) && (digits < 4) && (template[i] >= '0') && (template[i] <= '9'))
                    {
                        i++;
                        digits++;
                    }

                    if (digits == 0)
                        return false;
                }
                else if ((i < end) && (template[i] == '*'))
                {
                    i++;
                }

                if (i >= end)
                    return true;

                if (template[i] != ',')
                    return false;

                i++;

                if (i >= end)
                    return false;
            }

            return false;
        }

        static bool TryReadVariableName(string template, ref int i, int end, out string name)
        {
            StringBuilder value = new StringBuilder();

            if (!TryReadVariableChar(template, ref i, end, value))
            {
                name = null;
                return false;
            }

            while (i < end)
            {
                int saved = i;
                int savedLength = value.Length;

                if (template[i] == '.')
                {
                    i++;
                    value.Append('.');

                    if (!TryReadVariableChar(template, ref i, end, value))
                    {
                        i = saved;
                        value.Length = savedLength;
                        break;
                    }

                    continue;
                }

                if (!TryReadVariableChar(template, ref i, end, value))
                    break;
            }

            name = value.ToString();
            return true;
        }

        static bool TryReadVariableChar(string template, ref int i, int end, StringBuilder value)
        {
            if (i >= end)
                return false;

            char c = template[i];

            if (((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z')) || ((c >= '0') && (c <= '9')) || (c == '_'))
            {
                value.Append(c);
                i++;
                return true;
            }

            if ((c == '%') && (i + 2 < end) && Uri.IsHexDigit(template[i + 1]) && Uri.IsHexDigit(template[i + 2]))
            {
                value.Append((char)((HexValue(template[i + 1]) << 4) | HexValue(template[i + 2])));
                i += 3;
                return true;
            }

            return false;
        }

        static int HexValue(char c)
        {
            if ((c >= '0') && (c <= '9'))
                return c - '0';

            if ((c >= 'A') && (c <= 'F'))
                return c - 'A' + 10;

            return c - 'a' + 10;
        }

        static bool IsUriTemplateOperator(char c)
        {
            switch (c)
            {
                case '+':
                case '#':
                case '.':
                case '/':
                case ';':
                case '?':
                case '&':
                case '=':
                case ',':
                case '!':
                case '@':
                case '|':
                    return true;

                default:
                    return false;
            }
        }

        protected override void WriteSvcParamValue(Stream s)
        {
            s.Write(Encoding.UTF8.GetBytes(_dohPath));
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsSvcDoHPathParamValue other)
                return _dohPath.Equals(other._dohPath);

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_dohPath);
        }

        public override string ToString()
        {
            return _dohPath;
        }

        #endregion

        #region properties

        public string DoHPath
        { get { return _dohPath; } }

        public override int UncompressedLength
        { get { return Encoding.UTF8.GetByteCount(_dohPath); } }

        #endregion
    }
}
