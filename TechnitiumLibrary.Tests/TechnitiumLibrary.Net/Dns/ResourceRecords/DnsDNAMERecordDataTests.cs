using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsDNAMERecordDataTests
    {
        [TestMethod]
        public void Constructor_ValidInput_NormalizesDomain()
        {
            var rdata = new DnsDNAMERecordData("Example.COM.");

            Assert.AreEqual("example.com", rdata.Domain);
        }

        [TestMethod]
        public void Equals_DifferentDomain_IsFalse()
        {
            var a = new DnsDNAMERecordData("example.com.");
            var b = new DnsDNAMERecordData("example.net.");

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void Equals_SameDomain_IgnoresCase()
        {
            var a = new DnsDNAMERecordData("Example.COM.");
            var b = new DnsDNAMERecordData("example.com.");

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }
        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            var original = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.DNAME,
                DnsClass.IN,
                300,
                new DnsDNAMERecordData("target.example."));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            var parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            var rdata = new DnsDNAMERecordData("example.net.");

            using MemoryStream ms = new();
            using var writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = System.Text.Encoding.UTF8.GetString(ms.ToArray());

            StringAssert.Contains(json, "Domain");
            StringAssert.Contains(json, "example.net");
        }

        [TestMethod]
        public void Substitute_QnameNotInOwnerSubtree_Throws()
        {
            var rdata = new DnsDNAMERecordData("target.example.");

            Assert.ThrowsExactly<InvalidOperationException>(() =>
                rdata.Substitute(
                    qname: "www.other.com",
                    owner: "example.com"));
        }

        [TestMethod]
        public void Substitute_ReplacesOwnerSuffix_PerRFC6672()
        {
            var rdata = new DnsDNAMERecordData("target.example.");

            string result = rdata.Substitute(
                qname: "www.sub.example.com",
                owner: "example.com");

            Assert.AreEqual("www.sub.target.example", result);
        }

        [TestMethod]
        public void Substitute_ToRoot_RemovesOwnerSuffix()
        {
            var rdata = new DnsDNAMERecordData("");

            string result = rdata.Substitute(
                qname: "www.example.com",
                owner: "example.com");

            Assert.AreEqual("www", result);
        }
        [TestMethod]
        public void UncompressedLength_IsNonZero()
        {
            var rdata = new DnsDNAMERecordData("example.com.");

            Assert.IsTrue(rdata.UncompressedLength > 0);
        }

        private static byte[] Serialize(DnsResourceRecord rr)
        {
            using MemoryStream ms = new();
            rr.WriteTo(ms);
            return ms.ToArray();
        }
    }
}