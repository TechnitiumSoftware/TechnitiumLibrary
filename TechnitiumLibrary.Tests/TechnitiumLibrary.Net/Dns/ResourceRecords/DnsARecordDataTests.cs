using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Net;
using System.Text;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsARecordDataTests
    {
        [TestMethod]
        public void Constructor_NonIPv4_Throws()
        {
            var ipv6 = IPAddress.Parse("2001:db8::1");

            Assert.ThrowsExactly<DnsClientException>(() =>
                new DnsARecordData(ipv6));
        }

        [TestMethod]
        public void Constructor_ValidIPv4_Succeeds()
        {
            var ip = IPAddress.Parse("192.0.2.1");

            var rdata = new DnsARecordData(ip);

            Assert.AreEqual(ip, rdata.Address);
            Assert.AreEqual(4, rdata.UncompressedLength);
        }
        [TestMethod]
        public void Equals_DifferentAddress_AreNotEqual()
        {
            var a = new DnsARecordData(IPAddress.Parse("203.0.113.1"));
            var b = new DnsARecordData(IPAddress.Parse("203.0.113.2"));

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void Equals_SameAddress_AreEqual()
        {
            var a = new DnsARecordData(IPAddress.Parse("203.0.113.10"));
            var b = new DnsARecordData(IPAddress.Parse("203.0.113.10"));

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }
        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            var original = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.A,
                DnsClass.IN,
                300,
                new DnsARecordData(IPAddress.Parse("192.0.2.55")));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            var parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            var rdata = new DnsARecordData(IPAddress.Parse("198.51.100.42"));

            using MemoryStream ms = new();
            using var writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            StringAssert.Contains(json, "IPAddress");
            StringAssert.Contains(json, "198.51.100.42");
        }

        [TestMethod]
        public void UncompressedLength_MatchesWireRdataLength()
        {
            var rdata = new DnsARecordData(IPAddress.Parse("192.0.2.9"));

            var rr = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.A,
                DnsClass.IN,
                60,
                rdata);

            byte[] wire = Serialize(rr);

            Assert.IsTrue(rdata.UncompressedLength == 4);
            Assert.IsTrue(wire.Length >= rdata.UncompressedLength);
        }

        private static byte[] Serialize(DnsResourceRecord rr)
        {
            using MemoryStream ms = new();
            rr.WriteTo(ms);
            return ms.ToArray();
        }
    }
}