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
using System.Text;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsCNAMERecordDataTests
    {
        [TestMethod]
        public void Constructor_IDNDomain_IsConvertedToAscii()
        {
            DnsCNAMERecordData rdata = new DnsCNAMERecordData("bücher.example");

            Assert.AreEqual("xn--bcher-kva.example", rdata.Domain);
        }

        [TestMethod]
        public void Constructor_InvalidDomain_Throws()
        {
            Assert.ThrowsExactly<DnsClientException>(() =>
                new DnsCNAMERecordData("invalid..domain"));
        }

        [TestMethod]
        public void Constructor_ValidInput_Succeeds()
        {
            DnsCNAMERecordData rdata = new DnsCNAMERecordData("example.net");

            Assert.AreEqual("example.net", rdata.Domain);
        }

        [TestMethod]
        public void Equals_DifferentDomain_IsFalse()
        {
            DnsCNAMERecordData a = new DnsCNAMERecordData("a.example");
            DnsCNAMERecordData b = new DnsCNAMERecordData("b.example");

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void Equals_SameDomain_IgnoresCase()
        {
            DnsCNAMERecordData a = new DnsCNAMERecordData("Example.COM");
            DnsCNAMERecordData b = new DnsCNAMERecordData("example.com");

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            DnsResourceRecord original = new DnsResourceRecord(
                "www",
                DnsResourceRecordType.CNAME,
                DnsClass.IN,
                300,
                new DnsCNAMERecordData("target.example"));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            DnsResourceRecord parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            DnsCNAMERecordData rdata = new DnsCNAMERecordData("example.net");

            using MemoryStream ms = new();
            using System.Text.Json.Utf8JsonWriter writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            Assert.Contains("Domain", json);
            Assert.Contains("example.net", json);
        }

        [TestMethod]
        public void UncompressedLength_IsPositiveAndConsistent()
        {
            DnsCNAMERecordData rdata = new DnsCNAMERecordData("example.org");

            Assert.IsGreaterThan(0, rdata.UncompressedLength);

            DnsResourceRecord rr = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.CNAME,
                DnsClass.IN,
                60,
                rdata);

            byte[] wire = Serialize(rr);

            Assert.IsGreaterThanOrEqualTo(rdata.UncompressedLength, wire.Length);
        }

        private static byte[] Serialize(DnsResourceRecord rr)
        {
            using MemoryStream ms = new();
            rr.WriteTo(ms);
            return ms.ToArray();
        }
    }
}