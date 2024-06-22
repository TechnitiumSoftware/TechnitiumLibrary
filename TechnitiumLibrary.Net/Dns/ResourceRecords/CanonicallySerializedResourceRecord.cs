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
using System.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class CanonicallySerializedResourceRecord : IComparable<CanonicallySerializedResourceRecord>
    {
        #region variables

        readonly byte[] _firstPart;
        readonly byte[] _rdataPart;

        #endregion

        #region constructor

        private CanonicallySerializedResourceRecord(byte[] firstPart, byte[] rdataPart)
        {
            _firstPart = firstPart;
            _rdataPart = rdataPart;
        }

        #endregion

        #region static

        public static CanonicallySerializedResourceRecord Create(string name, DnsResourceRecordType type, DnsClass @class, uint originalTtl, DnsResourceRecordData rData, MemoryStream buffer)
        {
            byte[] firstPart;
            byte[] rdataPart;

            //serialize RDATA
            buffer.SetLength(0);
            rData.WriteCanonicalRecordData(buffer);

            rdataPart = buffer.ToArray();

            //serialize owner name | type | class | Original TTL | RDATA length
            buffer.SetLength(0);
            DnsDatagram.SerializeDomainName(name.ToLowerInvariant(), buffer);
            DnsDatagram.WriteUInt16NetworkOrder((ushort)type, buffer);
            DnsDatagram.WriteUInt16NetworkOrder((ushort)@class, buffer);
            DnsDatagram.WriteUInt32NetworkOrder(originalTtl, buffer);
            DnsDatagram.WriteUInt16NetworkOrder(Convert.ToUInt16(rdataPart.Length), buffer);

            firstPart = buffer.ToArray();

            //add to list
            return new CanonicallySerializedResourceRecord(firstPart, rdataPart);
        }

        #endregion

        #region public

        public int CompareTo(CanonicallySerializedResourceRecord other)
        {
            //Canonical RR Ordering by sorting RDATA portion of the canonical form of each RR
            return DnsNSECRecordData.CanonicalComparison(_rdataPart, other._rdataPart);
        }

        public void WriteTo(Stream s)
        {
            s.Write(_firstPart);
            s.Write(_rdataPart);
        }

        #endregion
    }
}
