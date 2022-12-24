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
using System.Text.Json;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public abstract class DnsResourceRecordData
    {
        #region variables

        protected ushort _rdLength;
        readonly bool _emptyRData;

        #endregion

        #region constructor

        protected DnsResourceRecordData()
        { }

        protected DnsResourceRecordData(Stream s)
        {
            //read RDLENGTH
            _rdLength = DnsDatagram.ReadUInt16NetworkOrder(s);

            //read RDATA
            if (_rdLength > 0)
                ReadRecordData(s);
            else
                _emptyRData = true;
        }

        #endregion

        #region protected

        protected abstract void ReadRecordData(Stream s);

        protected abstract void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm);

        #endregion

        #region internal

        internal virtual void NormalizeName()
        { }

        internal void WriteCanonicalRecordData(Stream s)
        {
            WriteRecordData(s, null, true);
        }

        #endregion

        #region public

        public void WriteTo(Stream s)
        {
            WriteTo(s, null);
        }

        public void WriteTo(Stream s, List<DnsDomainOffset> domainEntries)
        {
            if (_emptyRData)
            {
                Span<byte> buffer = stackalloc byte[2];
                s.Write(buffer);
            }
            else
            {
                long originalPosition = s.Position;

                //write dummy RDLENGTH
                s.Position += 2;

                //write RDATA
                WriteRecordData(s, domainEntries, false);

                long finalPosition = s.Position;

                //write actual RDLENGTH
                ushort length = Convert.ToUInt16(finalPosition - originalPosition - 2);
                s.Position = originalPosition;
                DnsDatagram.WriteUInt16NetworkOrder(length, s);

                s.Position = finalPosition;
            }
        }

        public override abstract bool Equals(object obj);

        public override abstract int GetHashCode();

        public override abstract string ToString();

        public abstract void SerializeTo(Utf8JsonWriter jsonWriter);

        #endregion

        #region properties

        public ushort RDLENGTH
        { get { return _rdLength; } }

        public abstract ushort UncompressedLength
        { get; }

        #endregion
    }
}
