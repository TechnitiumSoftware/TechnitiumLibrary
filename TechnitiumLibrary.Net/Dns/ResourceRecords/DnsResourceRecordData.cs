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

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public abstract class DnsResourceRecordData
    {
        #region variables

        protected ushort _rdLength;

        #endregion

        #region constructor

        protected DnsResourceRecordData()
        { }

        protected DnsResourceRecordData(Stream s)
        {
            //read RDLENGTH
            _rdLength = DnsDatagram.ReadUInt16NetworkOrder(s);

            //read RDATA
            ReadRecordData(s);
        }

        #endregion

        #region protected

        protected abstract void ReadRecordData(Stream s);

        protected abstract void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm);

        #endregion

        #region internal

        internal virtual void NormalizeName()
        { }

        #endregion

        #region public

        public void WriteTo(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            long originalPosition = s.Position;

            //write dummy RDLENGTH
            s.Position += 2;

            //write RDATA
            WriteRecordData(s, domainEntries, canonicalForm);

            long finalPosition = s.Position;

            //write actual RDLENGTH
            ushort length = Convert.ToUInt16(finalPosition - originalPosition - 2);
            s.Position = originalPosition;
            DnsDatagram.WriteUInt16NetworkOrder(length, s);

            s.Position = finalPosition;
        }

        public override abstract bool Equals(object obj);

        public override abstract int GetHashCode();

        public override abstract string ToString();

        #endregion

        #region properties

        [IgnoreDataMember]
        public ushort RDLENGTH
        { get { return _rdLength; } }

        [IgnoreDataMember]
        public abstract ushort UncompressedLength
        { get; }

        #endregion
    }
}
