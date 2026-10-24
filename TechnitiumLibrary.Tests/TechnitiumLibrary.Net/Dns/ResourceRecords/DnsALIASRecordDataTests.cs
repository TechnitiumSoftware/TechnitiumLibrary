using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Text;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsALIASRecordDataTests
    {
        [TestMethod]
        public void Constructor_ValidInput_Succeeds()
        {
            var rdata = new DnsALIASRecordData(
                DnsResourceRecordType.A,
                "example.net.");

            Assert.AreEqual(DnsResourceRecordType.A, rdata.Type);
            Assert.AreEqual("example.net", rdata.Domain); // It is expected to remove explicit root dot
        }

        [TestMethod]
        public void Equals_DifferentType_IsFalse()
        {
            var a = new DnsALIASRecordData(
                DnsResourceRecordType.A,
                "example.com.");

            var b = new DnsALIASRecordData(
                DnsResourceRecordType.AAAA,
                "example.com.");

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void Equals_SameTypeAndDomain_IgnoresCase()
        {
            var a = new DnsALIASRecordData(
                DnsResourceRecordType.AAAA,
                "Example.COM.");

            var b = new DnsALIASRecordData(
                DnsResourceRecordType.AAAA,
                "example.com.");

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            var original = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.ALIAS,
                DnsClass.IN,
                300,
                new DnsALIASRecordData(
                    DnsResourceRecordType.A,
                    "target.example."));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            var parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            var rdata = new DnsALIASRecordData(
                DnsResourceRecordType.AAAA,
                "example.net.");

            using MemoryStream ms = new();
            using var writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            StringAssert.Contains(json, "Type");
            StringAssert.Contains(json, "AAAA");
            StringAssert.Contains(json, "Domain");
            StringAssert.Contains(json, "example.net");
        }

        [TestMethod]
        public void UncompressedLength_IncludesTypePrefix()
        {
            var rdata = new DnsALIASRecordData(
                DnsResourceRecordType.A,
                "example.com.");

            int baseLength = rdata.Domain.Length; // not exact, but sanity check

            Assert.IsTrue(rdata.UncompressedLength > baseLength);
            Assert.IsTrue(rdata.UncompressedLength >= 2);
        }

        private static byte[] Serialize(DnsResourceRecord rr)
        {
            using MemoryStream ms = new();
            rr.WriteTo(ms);
            return ms.ToArray();
        }
    }
}