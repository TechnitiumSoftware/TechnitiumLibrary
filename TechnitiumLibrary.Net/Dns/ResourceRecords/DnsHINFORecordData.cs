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
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsHINFORecordData : DnsResourceRecordData
    {
        #region variables

        string _cpu;
        string _os;

        #endregion

        #region constructors

        public DnsHINFORecordData(string cpu, string os)
        {
            _cpu = cpu;
            _os = os;
        }

        public DnsHINFORecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _cpu = Encoding.ASCII.GetString(s.ReadExactly(s.ReadByteValue()));
            _os = Encoding.ASCII.GetString(s.ReadExactly(s.ReadByteValue()));
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            s.WriteByte(Convert.ToByte(_cpu.Length));
            s.Write(Encoding.ASCII.GetBytes(_cpu));

            s.WriteByte(Convert.ToByte(_os.Length));
            s.Write(Encoding.ASCII.GetBytes(_os));
        }

        #endregion

        #region internal

        internal static async Task<DnsHINFORecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsHINFORecordData(rdata);

            string cpu = await zoneFile.PopItemAsync();
            string os = await zoneFile.PopItemAsync();

            return new DnsHINFORecordData(cpu, os);
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            return DnsDatagram.EncodeCharacterString(_cpu) + " " + DnsDatagram.EncodeCharacterString(_os);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsHINFORecordData other)
                return _cpu.Equals(other._cpu) && _os.Equals(other._os);

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_cpu, _os);
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("CPU", _cpu);
            jsonWriter.WriteString("OS", _os);

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public string CPU
        { get { return _cpu; } }

        public string OS
        { get { return _os; } }

        public override int UncompressedLength
        { get { return 1 + _cpu.Length + 1 + _os.Length; } }

        #endregion
    }
}
