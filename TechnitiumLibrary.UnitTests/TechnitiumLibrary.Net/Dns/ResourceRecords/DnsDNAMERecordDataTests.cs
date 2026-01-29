using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsDNAMERecordDataTests
    {
        [TestMethod]
        public void Constructor_ValidInput_NormalizesDomain()
        {
            DnsDNAMERecordData rdata = new DnsDNAMERecordData("Example.COM");

            Assert.AreEqual("example.com", rdata.Domain);
        }

        [TestMethod]
        public void Equals_DifferentDomain_IsFalse()
        {
            DnsDNAMERecordData a = new DnsDNAMERecordData("example.com");
            DnsDNAMERecordData b = new DnsDNAMERecordData("example.net");

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void Equals_SameDomain_IgnoresCase()
        {
            DnsDNAMERecordData a = new DnsDNAMERecordData("Example.COM");
            DnsDNAMERecordData b = new DnsDNAMERecordData("example.com");

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            DnsResourceRecord original = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.DNAME,
                DnsClass.IN,
                300,
                new DnsDNAMERecordData("target.example"));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            DnsResourceRecord parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            DnsDNAMERecordData rdata = new DnsDNAMERecordData("example.net");

            using MemoryStream ms = new();
            using System.Text.Json.Utf8JsonWriter writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = System.Text.Encoding.UTF8.GetString(ms.ToArray());

            Assert.Contains("Domain", json);
            Assert.Contains("example.net", json);
        }

        [TestMethod]
        public void Substitute_QnameNotInOwnerSubtree_Throws()
        {
            DnsDNAMERecordData rdata = new DnsDNAMERecordData("target.example");

            Assert.ThrowsExactly<InvalidOperationException>(() =>
                rdata.Substitute(
                    qname: "www.other.com",
                    owner: "example.com"));
        }

        [TestMethod]
        public void Substitute_ReplacesOwnerSuffix_PerRFC6672()
        {
            DnsDNAMERecordData rdata = new DnsDNAMERecordData("target.example");

            string result = rdata.Substitute(
                qname: "www.sub.example.com",
                owner: "example.com");

            Assert.AreEqual("www.sub.target.example", result);
        }

        [TestMethod]
        public void Substitute_ToRoot_RemovesOwnerSuffix()
        {
            DnsDNAMERecordData rdata = new DnsDNAMERecordData("");

            string result = rdata.Substitute(
                qname: "www.example.com",
                owner: "example.com");

            Assert.AreEqual("www", result);
        }

        [TestMethod]
        public void UncompressedLength_IsNonZero()
        {
            DnsDNAMERecordData rdata = new DnsDNAMERecordData("example.com");

            Assert.IsGreaterThan(0, rdata.UncompressedLength);
        }

        private static byte[] Serialize(DnsResourceRecord rr)
        {
            using MemoryStream ms = new();
            rr.WriteTo(ms);
            return ms.ToArray();
        }
    }
}