using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Net;
using System.Text;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsARecordDataTests
    {
        [TestMethod]
        public void Constructor_NonIPv4_Throws()
        {
            IPAddress ipv6 = IPAddress.Parse("2001:db8::1");

            Assert.ThrowsExactly<DnsClientException>(() =>
                new DnsARecordData(ipv6));
        }

        [TestMethod]
        public void Constructor_ValidIPv4_Succeeds()
        {
            IPAddress ip = IPAddress.Parse("192.0.2.1");

            DnsARecordData rdata = new DnsARecordData(ip);

            Assert.AreEqual(ip, rdata.Address);
            Assert.AreEqual(4, rdata.UncompressedLength);
        }

        [TestMethod]
        public void Equals_DifferentAddress_AreNotEqual()
        {
            DnsARecordData a = new DnsARecordData(IPAddress.Parse("203.0.113.1"));
            DnsARecordData b = new DnsARecordData(IPAddress.Parse("203.0.113.2"));

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void Equals_SameAddress_AreEqual()
        {
            DnsARecordData a = new DnsARecordData(IPAddress.Parse("203.0.113.10"));
            DnsARecordData b = new DnsARecordData(IPAddress.Parse("203.0.113.10"));

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            DnsResourceRecord original = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.A,
                DnsClass.IN,
                300,
                new DnsARecordData(IPAddress.Parse("192.0.2.55")));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            DnsResourceRecord parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            DnsARecordData rdata = new DnsARecordData(IPAddress.Parse("198.51.100.42"));

            using MemoryStream ms = new();
            using System.Text.Json.Utf8JsonWriter writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            Assert.Contains("IPAddress", json);
            Assert.Contains("198.51.100.42", json);
        }

        [TestMethod]
        public void UncompressedLength_MatchesWireRdataLength()
        {
            DnsARecordData rdata = new DnsARecordData(IPAddress.Parse("192.0.2.9"));

            DnsResourceRecord rr = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.A,
                DnsClass.IN,
                60,
                rdata);

            byte[] wire = Serialize(rr);

            Assert.AreEqual(4, rdata.UncompressedLength);
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