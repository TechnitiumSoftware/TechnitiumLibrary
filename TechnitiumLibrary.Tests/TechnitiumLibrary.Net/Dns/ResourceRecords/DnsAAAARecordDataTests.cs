using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Net;
using System.Text;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Dns.ResourceRecords
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

            var rdata = new DnsAAAARecordData(address);

            Assert.AreEqual(address, rdata.Address);
            Assert.AreEqual(16, rdata.UncompressedLength);
        }

        [TestMethod]
        public void Equals_DifferentAddress_IsFalse()
        {
            var a = new DnsAAAARecordData(IPAddress.Parse("2001:db8::1"));
            var b = new DnsAAAARecordData(IPAddress.Parse("2001:db8::2"));

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void Equals_SameAddress_IsTrue()
        {
            IPAddress address = IPAddress.Parse("2001:db8::1");

            var a = new DnsAAAARecordData(address);
            var b = new DnsAAAARecordData(IPAddress.Parse("2001:db8::1"));

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            IPAddress address = IPAddress.Parse("2001:db8::dead:beef");

            var original = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.AAAA,
                DnsClass.IN,
                300,
                new DnsAAAARecordData(address));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            var parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            var rdata = new DnsAAAARecordData(IPAddress.Parse("2001:db8::1"));

            using MemoryStream ms = new();
            using var writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            StringAssert.Contains(json, "IPAddress");
            StringAssert.Contains(json, "2001:db8::1");
        }

        [TestMethod]
        public void UncompressedLength_IsAlways16()
        {
            var rdata = new DnsAAAARecordData(IPAddress.Parse("2001:db8::abcd"));

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