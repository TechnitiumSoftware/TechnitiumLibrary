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
using System.Text.Json;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    [Flags]
    public enum EDnsHeaderFlags : ushort
    {
        None = 0,
        DNSSEC_OK = 0x8000
    }

    public class DnsDatagramEdns
    {
        #region variables

        readonly ushort _udpPayloadSize;
        readonly DnsResponseCode _extendedRCODE;
        readonly byte _version;
        readonly EDnsHeaderFlags _flags;
        readonly IReadOnlyList<EDnsOption> _options;

        #endregion

        #region constructor

        public DnsDatagramEdns(ushort udpPayloadSize, DnsResponseCode extendedRCODE, byte version, EDnsHeaderFlags flags, IReadOnlyList<EDnsOption> options)
        {
            _udpPayloadSize = udpPayloadSize;
            _extendedRCODE = extendedRCODE;
            _version = version;
            _flags = flags;
            _options = options;

            if (_udpPayloadSize < 512)
                _udpPayloadSize = 512;

            if (_options is null)
                _options = Array.Empty<EDnsOption>();
        }

        #endregion

        #region static

        public static DnsDatagramEdns ReadOPTFrom(IReadOnlyList<DnsResourceRecord> additional, DnsResponseCode RCODE)
        {
            DnsResourceRecord opt = null;

            foreach (DnsResourceRecord record in additional)
            {
                if (record.Type == DnsResourceRecordType.OPT)
                {
                    opt = record;
                    break;
                }
            }

            if (opt is null)
                return null;

            return new DnsDatagramEdns((ushort)opt.Class, (DnsResponseCode)(((opt.OriginalTtlValue & 0xff000000u) >> 20) | ((uint)RCODE & 0xfu)), (byte)((opt.OriginalTtlValue >> 16) & 0xffu), (EDnsHeaderFlags)(opt.OriginalTtlValue & 0xffffu), (opt.RDATA as DnsOPTRecordData).Options);
        }

        public static DnsResourceRecord GetOPTFor(ushort udpPayloadSize, DnsResponseCode extendedRCODE, byte version, EDnsHeaderFlags flags, IReadOnlyList<EDnsOption> options)
        {
            DnsOPTRecordData opt;

            if ((options is null) || (options.Count == 0))
                opt = DnsOPTRecordData.Empty;
            else
                opt = new DnsOPTRecordData(options);

            return new DnsResourceRecord("", DnsResourceRecordType.OPT, (DnsClass)udpPayloadSize, ((((uint)extendedRCODE) & 0x00000ff0u) << 20) | (((uint)version) << 16) | ((uint)flags), opt);
        }

        #endregion

        #region public

        public void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteNumber("UdpPayloadSize", _udpPayloadSize);
            jsonWriter.WriteString("ExtendedRCODE", _extendedRCODE.ToString());
            jsonWriter.WriteNumber("Version", _version);
            jsonWriter.WriteString("Flags", _flags.ToString());

            jsonWriter.WritePropertyName("Options");
            jsonWriter.WriteStartArray();

            foreach (EDnsOption option in _options)
                option.SerializeTo(jsonWriter);

            jsonWriter.WriteEndArray();

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public ushort UdpPayloadSize
        { get { return _udpPayloadSize; } }

        public DnsResponseCode ExtendedRCODE
        { get { return _extendedRCODE; } }

        public byte Version
        { get { return _version; } }

        public EDnsHeaderFlags Flags
        { get { return _flags; } }

        public IReadOnlyList<EDnsOption> Options
        { get { return _options; } }

        #endregion
    }
}
