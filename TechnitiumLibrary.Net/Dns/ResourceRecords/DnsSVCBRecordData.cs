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

                while (mS.Position < mS.Length)
                {
                    DnsSvcParamKey svcParamKey = (DnsSvcParamKey)DnsDatagram.ReadUInt16NetworkOrder(mS);
                    DnsSvcParamValue svcParamValue;

                    switch (svcParamKey)
                    {
                        case DnsSvcParamKey.Mandatory:
                            svcParamValue = new DnsSvcMandatoryParamValue(mS);
                            break;

                        case DnsSvcParamKey.ALPN:
                        case DnsSvcParamKey.No_Default_ALPN:
                            svcParamValue = new DnsSvcAlpnParamValue(mS);
                            break;

                        case DnsSvcParamKey.Port:
                            svcParamValue = new DnsSvcPortParamValue(mS);
                            break;

                        case DnsSvcParamKey.IPv4Hint:
                            svcParamValue = new DnsSvcIPv4HintParamValue(mS);
                            break;

                        case DnsSvcParamKey.IPv6Hint:
                            svcParamValue = new DnsSvcIPv6HintParamValue(mS);
                            break;

                        case DnsSvcParamKey.DoHPath:
                            svcParamValue = new DnsSvcDoHPathParamValue(mS);
                            break;

                        default:
                            svcParamValue = new DnsSvcUnknownParamValue(mS);
                            break;
                    }

                    _ = svcParams.TryAdd(svcParamKey, svcParamValue);
                }

                _svcParams = svcParams;
            }
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            if (_rData is null)
            {
                List<KeyValuePair<DnsSvcParamKey, DnsSvcParamValue>> svcParams = new List<KeyValuePair<DnsSvcParamKey, DnsSvcParamValue>>(_svcParams);

                svcParams.Sort(delegate (KeyValuePair<DnsSvcParamKey, DnsSvcParamValue> x, KeyValuePair<DnsSvcParamKey, DnsSvcParamValue> y)
                {
                    return ((ushort)x.Key).CompareTo((ushort)y.Key);
                });

                using (MemoryStream mS = new MemoryStream(UncompressedLength))
                {
                    DnsDatagram.WriteUInt16NetworkOrder(_svcPriority, mS);
                    DnsDatagram.SerializeDomainName(canonicalForm ? _targetName.ToLowerInvariant() : _targetName, mS, null); //no compression for domain name as per RFC

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
                if (i < 0)
                    svcParamKey = Enum.Parse<DnsSvcParamKey>(param.Replace('-', '_'), true);
                else
                    svcParamKey = Enum.Parse<DnsSvcParamKey>(param.Substring(0, i).Replace('-', '_'), true);

                svcParamValue = param.Substring(i + 1);

                switch (svcParamKey)
                {
                    case DnsSvcParamKey.IPv4Hint:
                        if (svcParamValue.Equals("auto", StringComparison.OrdinalIgnoreCase))
                        {
                            autoIpv4Hint = true;
                            continue;
                        }
                        break;

                    case DnsSvcParamKey.IPv6Hint:
                        if (svcParamValue.Equals("auto", StringComparison.OrdinalIgnoreCase))
                        {
                            autoIpv6Hint = true;
                            continue;
                        }
                        break;
                }

                svcParams.Add(svcParamKey, DnsSvcParamValue.Parse(svcParamKey, svcParamValue));
            }
            while (true);

            return new DnsSVCBRecordData(svcPriority, targetName, svcParams) { _autoIpv4Hint = autoIpv4Hint, _autoIpv6Hint = autoIpv6Hint };
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            string svcParams = string.Empty;

            foreach (KeyValuePair<DnsSvcParamKey, DnsSvcParamValue> svcParam in _svcParams)
            {
                switch (svcParam.Key)
                {
                    case DnsSvcParamKey.No_Default_ALPN:
                        svcParams += " " + svcParam.Key.ToString().ToLowerInvariant().Replace('_', '-');
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
                        svcParams += " " + svcParam.Key.ToString().ToLowerInvariant().Replace('_', '-') + "=" + svcParam.Value.ToString();
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

                if (!_targetName.Equals(other._targetName, StringComparison.OrdinalIgnoreCase))
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
            return HashCode.Combine(_svcPriority, _targetName, _svcParams.GetArrayHashCode());
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

        #endregion

        #region constructors

        protected DnsSvcParamValue()
        { }

        public DnsSvcParamValue(Stream s)
        {
            _length = DnsDatagram.ReadUInt16NetworkOrder(s);

            ReadSvcParamValue(s);
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
                return BinaryNumber.Equals(_value, other._value);

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
            return new DnsSvcMandatoryParamValue(svcParamValue.Split(delegate (string value)
            {
                return Enum.Parse<DnsSvcParamKey>(value.Replace('-', '_'), true);
            }, ','));
        }

        #endregion

        #region protected

        protected override void ReadSvcParamValue(Stream s)
        {
            int count = _length / 2;
            DnsSvcParamKey[] keys = new DnsSvcParamKey[count];

            for (int i = 0; i < count; i++)
                keys[i] = (DnsSvcParamKey)DnsDatagram.ReadUInt16NetworkOrder(s);

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
                    value = key.ToString().ToLowerInvariant().Replace('_', '-');
                else
                    value += "," + key.ToString().ToLowerInvariant().Replace('_', '-');
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

            _alpnIds = alpnIds;
        }

        public DnsSvcAlpnParamValue(Stream s)
            : base(s)
        { }

        #endregion

        #region static

        public static DnsSvcAlpnParamValue Parse(string svcParamValue)
        {
            return new DnsSvcAlpnParamValue(svcParamValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
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

                alpnIds.Add(Encoding.ASCII.GetString(s.ReadExactly(alpnLength)));

                bytesRead += alpnLength + 1;
            }

            _alpnIds = alpnIds;
        }

        protected override void WriteSvcParamValue(Stream s)
        {
            foreach (string alpnId in _alpnIds)
            {
                s.WriteByte(Convert.ToByte(alpnId.Length));
                s.Write(Encoding.ASCII.GetBytes(alpnId));
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
                    if (!_alpnIds[i].Equals(other._alpnIds[i], StringComparison.OrdinalIgnoreCase))
                        return false;
                }

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return _alpnIds.GetArrayHashCode();
        }

        public override string ToString()
        {
            string value = null;

            foreach (string alpnId in _alpnIds)
            {
                if (value is null)
                    value = alpnId;
                else
                    value += "," + alpnId;
            }

            return value;
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
            return new DnsSvcIPv4HintParamValue(svcParamValue.Split(IPAddress.Parse, ','));
        }

        #endregion

        #region protected

        protected override void ReadSvcParamValue(Stream s)
        {
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
            return new DnsSvcIPv6HintParamValue(svcParamValue.Split(IPAddress.Parse, ','));
        }

        #endregion

        #region protected

        protected override void ReadSvcParamValue(Stream s)
        {
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

            if (!dohPath.Contains("{?dns}"))
                throw new ArgumentException("DoH path template must contain a 'dns' variable.");

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
