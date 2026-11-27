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
using System;
using System.IO;
using System.Text;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsDSRecordDataTests
    {
        [TestMethod]
        public void Constructor_InvalidDigestLength_Throws()
        {
            byte[] invalidDigest = new byte[10];

            Assert.ThrowsExactly<ArgumentException>(() =>
                new DnsDSRecordData(
                    keyTag: 1,
                    algorithm: DnssecAlgorithm.RSASHA256,
                    digestType: DnssecDigestType.SHA256,
                    digest: invalidDigest));
        }

        [TestMethod]
        public void Constructor_ValidSHA256_Succeeds()
        {
            byte[] digest = new byte[32];
            Random.Shared.NextBytes(digest);

            DnsDSRecordData rdata = new DnsDSRecordData(
                keyTag: 12345,
                algorithm: DnssecAlgorithm.RSASHA256,
                digestType: DnssecDigestType.SHA256,
                digest: digest);

            Assert.AreEqual((ushort)12345, rdata.KeyTag);
            Assert.AreEqual(DnssecAlgorithm.RSASHA256, rdata.Algorithm);
            Assert.AreEqual(DnssecDigestType.SHA256, rdata.DigestType);
            CollectionAssert.AreEqual(digest, rdata.Digest);
        }

        [TestMethod]
        public void Equals_DifferentDigest_IsFalse()
        {
            byte[] digestA = new byte[20];
            byte[] digestB = new byte[20];
            Random.Shared.NextBytes(digestA);
            Random.Shared.NextBytes(digestB);

            DnsDSRecordData a = new DnsDSRecordData(
                10,
                DnssecAlgorithm.RSASHA1,
                DnssecDigestType.SHA1,
                digestA);

            DnsDSRecordData b = new DnsDSRecordData(
                10,
                DnssecAlgorithm.RSASHA1,
                DnssecDigestType.SHA1,
                digestB);

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void Equals_SameValues_AreEqual()
        {
            byte[] digest = new byte[20];
            Random.Shared.NextBytes(digest);

            DnsDSRecordData a = new DnsDSRecordData(
                10,
                DnssecAlgorithm.RSASHA1,
                DnssecDigestType.SHA1,
                digest);

            DnsDSRecordData b = new DnsDSRecordData(
                10,
                DnssecAlgorithm.RSASHA1,
                DnssecDigestType.SHA1,
                digest);

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void IsDigestTypeSupported_WorksAsSpecified()
        {
            Assert.IsTrue(DnsDSRecordData.IsDigestTypeSupported(DnssecDigestType.SHA1));
            Assert.IsTrue(DnsDSRecordData.IsDigestTypeSupported(DnssecDigestType.SHA256));
            Assert.IsFalse(DnsDSRecordData.IsDigestTypeSupported(DnssecDigestType.GOST_R_34_11_94));
        }

        [TestMethod]
        public void IsDnssecAlgorithmSupported_WorksAsSpecified()
        {
            Assert.IsTrue(DnsDSRecordData.IsDnssecAlgorithmSupported(DnssecAlgorithm.RSASHA256));
            Assert.IsTrue(DnsDSRecordData.IsDnssecAlgorithmSupported(DnssecAlgorithm.ED25519));
            Assert.IsFalse(DnsDSRecordData.IsDnssecAlgorithmSupported(DnssecAlgorithm.RSAMD5));
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            byte[] digest = new byte[32];
            Random.Shared.NextBytes(digest);

            DnsResourceRecord original = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.DS,
                DnsClass.IN,
                3600,
                new DnsDSRecordData(
                    54321,
                    DnssecAlgorithm.RSASHA256,
                    DnssecDigestType.SHA256,
                    digest));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            DnsResourceRecord parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            byte[] digest = new byte[32];
            Random.Shared.NextBytes(digest);

            DnsDSRecordData rdata = new DnsDSRecordData(
                100,
                DnssecAlgorithm.RSASHA256,
                DnssecDigestType.SHA256,
                digest);

            using MemoryStream ms = new();
            using System.Text.Json.Utf8JsonWriter writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            Assert.Contains("KeyTag", json);
            Assert.Contains("Algorithm", json);
            Assert.Contains("DigestType", json);
            Assert.Contains("Digest", json);
        }

        [TestMethod]
        public void UncompressedLength_MatchesExpected()
        {
            byte[] digest = new byte[48];
            Random.Shared.NextBytes(digest);

            DnsDSRecordData rdata = new DnsDSRecordData(
                1,
                DnssecAlgorithm.ECDSAP384SHA384,
                DnssecDigestType.SHA384,
                digest);

            Assert.AreEqual(2 + 1 + 1 + 48, rdata.UncompressedLength);
        }

        private static byte[] Serialize(DnsResourceRecord rr)
        {
            using MemoryStream ms = new();
            rr.WriteTo(ms);
            return ms.ToArray();
        }
    }
}