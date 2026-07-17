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
using System.Text;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsAAAARecordDataTests
    {
        [TestMethod]
        public void Constructor_IPv4Address_Throws()
        {
            IPAddress ipv4 = IPAddress.Parse("192.0.2.1");

            Assert.ThrowsExactly<DnsClientException>(() =>
                new DnsAAAARecordData(ipv4));
        }

        [TestMethod]
        public void Constructor_ValidIPv6Address_Succeeds()
        {
            IPAddress address = IPAddress.Parse("2001:db8::1");

            DnsAAAARecordData rdata = new DnsAAAARecordData(address);

            Assert.AreEqual(address, rdata.Address);
            Assert.AreEqual(16, rdata.UncompressedLength);
        }

        [TestMethod]
        public void Equals_DifferentAddress_IsFalse()
        {
            DnsAAAARecordData a = new DnsAAAARecordData(IPAddress.Parse("2001:db8::1"));
            DnsAAAARecordData b = new DnsAAAARecordData(IPAddress.Parse("2001:db8::2"));

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void Equals_SameAddress_IsTrue()
        {
            IPAddress address = IPAddress.Parse("2001:db8::1");

            DnsAAAARecordData a = new DnsAAAARecordData(address);
            DnsAAAARecordData b = new DnsAAAARecordData(IPAddress.Parse("2001:db8::1"));

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            IPAddress address = IPAddress.Parse("2001:db8::dead:beef");

            DnsResourceRecord original = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.AAAA,
                DnsClass.IN,
                300,
                new DnsAAAARecordData(address));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            DnsResourceRecord parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            DnsAAAARecordData rdata = new DnsAAAARecordData(IPAddress.Parse("2001:db8::1"));

            using MemoryStream ms = new();
            using System.Text.Json.Utf8JsonWriter writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            Assert.Contains("IPAddress", json);
            Assert.Contains("2001:db8::1", json);
        }

        [TestMethod]
        public void UncompressedLength_IsAlways16()
        {
            DnsAAAARecordData rdata = new DnsAAAARecordData(IPAddress.Parse("2001:db8::abcd"));

            Assert.AreEqual(16, rdata.UncompressedLength);
        }

        private static byte[] Serialize(DnsResourceRecord rr)
        {
            using MemoryStream ms = new();
            rr.WriteTo(ms);
            return ms.ToArray();
        }
    }
}