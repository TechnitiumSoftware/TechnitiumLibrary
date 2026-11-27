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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Net;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class CanonicallySerializedResourceRecordTests
    {
        [TestMethod]
        public void CompareTo_UsesCanonicalRdataOrdering()
        {
            using MemoryStream buffer = new();

            CanonicallySerializedResourceRecord low = CanonicallySerializedResourceRecord.Create(
                "example.com",
                DnsResourceRecordType.A,
                DnsClass.IN,
                60,
                new DnsARecordData(IPAddress.Parse("192.0.2.1")),
                buffer);

            CanonicallySerializedResourceRecord high = CanonicallySerializedResourceRecord.Create(
                "example.com",
                DnsResourceRecordType.A,
                DnsClass.IN,
                60,
                new DnsARecordData(IPAddress.Parse("192.0.2.200")),
                buffer);

            Assert.IsLessThan(0, low.CompareTo(high));
            Assert.IsGreaterThan(0, high.CompareTo(low));
        }

        [TestMethod]
        public void Create_CanonicalizesOwnerName_ToLowercase()
        {
            using MemoryStream buffer = new();

            CanonicallySerializedResourceRecord record = CanonicallySerializedResourceRecord.Create(
                name: "Example.COM",
                type: DnsResourceRecordType.A,
                @class: DnsClass.IN,
                originalTtl: 3600,
                rData: new DnsARecordData(IPAddress.Parse("192.0.2.1")),
                buffer: buffer);

            using MemoryStream ms = new();
            record.WriteTo(ms);

            string wire = System.Text.Encoding.ASCII.GetString(ms.ToArray());
            Assert.Contains("example", wire);
        }

        [TestMethod]
        public void WriteTo_IsDeterministic_ForSameInput()
        {
            using MemoryStream buffer = new();

            CanonicallySerializedResourceRecord a = CanonicallySerializedResourceRecord.Create(
                "example.com",
                DnsResourceRecordType.A,
                DnsClass.IN,
                60,
                new DnsARecordData(IPAddress.Parse("192.0.2.1")),
                buffer);

            CanonicallySerializedResourceRecord b = CanonicallySerializedResourceRecord.Create(
                "example.com",
                DnsResourceRecordType.A,
                DnsClass.IN,
                60,
                new DnsARecordData(IPAddress.Parse("192.0.2.1")),
                buffer);

            using MemoryStream m1 = new();
            using MemoryStream m2 = new();

            a.WriteTo(m1);
            b.WriteTo(m2);

            CollectionAssert.AreEqual(m1.ToArray(), m2.ToArray());
        }
    }
}