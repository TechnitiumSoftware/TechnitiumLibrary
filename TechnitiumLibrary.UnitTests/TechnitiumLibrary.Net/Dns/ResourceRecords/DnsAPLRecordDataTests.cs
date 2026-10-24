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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsAPLRecordDataTests
    {
        [TestMethod]
        public void Constructor_SingleNetworkAddress_Succeeds()
        {
            NetworkAddress network = new NetworkAddress(IPAddress.Parse("192.0.2.0"), 24);

            DnsAPLRecordData rdata = new DnsAPLRecordData(network, negation: false);

            Assert.HasCount(1, rdata.APItems);
            Assert.AreEqual(IanaAddressFamily.IPv4, rdata.APItems.First().AddressFamily);
            Assert.AreEqual(24, rdata.APItems.First().Prefix);
            Assert.IsFalse(rdata.APItems.First().Negation);
        }

        [TestMethod]
        public void APItem_NegationFlag_Preserved()
        {
            NetworkAddress network = new NetworkAddress(IPAddress.Parse("2001:db8::"), 32);

            DnsAPLRecordData.APItem item = new DnsAPLRecordData.APItem(network, negation: true);

            Assert.IsTrue(item.Negation);
            Assert.AreEqual(IanaAddressFamily.IPv6, item.AddressFamily);
        }

        [TestMethod]
        public void Equals_SameItems_AreEqual()
        {
            List<DnsAPLRecordData.APItem> list1 = new List<DnsAPLRecordData.APItem>
            {
                new(new NetworkAddress(IPAddress.Parse("192.0.2.0"), 24), false),
                new(new NetworkAddress(IPAddress.Parse("198.51.100.0"), 24), true)
            };

            List<DnsAPLRecordData.APItem> list2 = new List<DnsAPLRecordData.APItem>
            {
                new(new NetworkAddress(IPAddress.Parse("192.0.2.0"), 24), false),
                new(new NetworkAddress(IPAddress.Parse("198.51.100.0"), 24), true)
            };

            DnsAPLRecordData a = new DnsAPLRecordData(list1);
            DnsAPLRecordData b = new DnsAPLRecordData(list2);

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void Equals_DifferentItems_AreNotEqual()
        {
            DnsAPLRecordData a = new DnsAPLRecordData(
                new NetworkAddress(IPAddress.Parse("192.0.2.0"), 24), false);

            DnsAPLRecordData b = new DnsAPLRecordData(
                new NetworkAddress(IPAddress.Parse("192.0.2.0"), 25), false);

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            DnsAPLRecordData rdata = new DnsAPLRecordData(new List<DnsAPLRecordData.APItem>
            {
                new(new NetworkAddress(IPAddress.Parse("192.0.2.0"), 24), false),
                new(new NetworkAddress(IPAddress.Parse("2001:db8::"), 32), true)
            });

            DnsResourceRecord rr = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.APL,
                DnsClass.IN,
                300,
                rdata);

            byte[] wire = Serialize(rr);

            using MemoryStream ms = new(wire);
            DnsResourceRecord parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(rr, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesJsonArray()
        {
            DnsAPLRecordData rdata = new DnsAPLRecordData(
                new NetworkAddress(IPAddress.Parse("192.0.2.0"), 24), false);

            using MemoryStream ms = new();
            using System.Text.Json.Utf8JsonWriter writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            Assert.StartsWith("[", json);
            Assert.Contains("IPv4", json);
            Assert.Contains("Prefix", json);
        }

        [TestMethod]
        public void UncompressedLength_MatchesSumOfItems()
        {
            List<DnsAPLRecordData.APItem> items = new List<DnsAPLRecordData.APItem>
            {
                new(new NetworkAddress(IPAddress.Parse("192.0.2.0"), 24), false),
                new(new NetworkAddress(IPAddress.Parse("198.51.100.0"), 25), true)
            };

            DnsAPLRecordData rdata = new DnsAPLRecordData(items);

            int expected = 0;
            foreach (DnsAPLRecordData.APItem item in items)
                expected += item.UncompressedLength;

            Assert.AreEqual(expected, rdata.UncompressedLength);
        }

        private static byte[] Serialize(DnsResourceRecord rr)
        {
            using MemoryStream ms = new();
            rr.WriteTo(ms);
            return ms.ToArray();
        }
    }
}