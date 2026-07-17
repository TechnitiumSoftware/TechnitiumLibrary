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
    public class DnsMXRecordDataTests
    {
        [TestMethod]
        public void Constructor_ValidInput_Succeeds()
        {
            DnsMXRecordData rdata = new DnsMXRecordData(
                preference: 10,
                exchange: "mail.example.com");

            Assert.AreEqual((ushort)10, rdata.Preference);
            Assert.AreEqual("mail.example.com", rdata.Exchange);
        }

        [TestMethod]
        public void Equals_SameValues_IgnoresCaseOnExchange()
        {
            DnsMXRecordData a = new DnsMXRecordData(
                10,
                "Mail.EXAMPLE.COM");

            DnsMXRecordData b = new DnsMXRecordData(
                10,
                "mail.example.com");

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void Equals_DifferentPreference_IsFalse()
        {
            DnsMXRecordData a = new DnsMXRecordData(10, "mail.example.com");
            DnsMXRecordData b = new DnsMXRecordData(20, "mail.example.com");

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void Equals_DifferentExchange_IsFalse()
        {
            DnsMXRecordData a = new DnsMXRecordData(10, "mail1.example.com");
            DnsMXRecordData b = new DnsMXRecordData(10, "mail2.example.com");

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void CompareTo_OrdersByPreference()
        {
            DnsMXRecordData low = new DnsMXRecordData(5, "a.example");
            DnsMXRecordData high = new DnsMXRecordData(20, "b.example");

            Assert.IsLessThan(0, low.CompareTo(high));
            Assert.IsGreaterThan(0, high.CompareTo(low));
            Assert.AreEqual(0, low.CompareTo(new DnsMXRecordData(5, "other.example")));
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            DnsResourceRecord original = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.MX,
                DnsClass.IN,
                3600,
                new DnsMXRecordData(
                    10,
                    "mail.example"));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            DnsResourceRecord parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            DnsMXRecordData rdata = new DnsMXRecordData(
                10,
                "mail.example.com");

            using MemoryStream ms = new();
            using System.Text.Json.Utf8JsonWriter writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            Assert.Contains("Preference", json);
            Assert.Contains("10", json);
            Assert.Contains("Exchange", json);
            Assert.Contains("mail.example.com", json);
        }

        [TestMethod]
        public void UncompressedLength_MatchesFormula()
        {
            DnsMXRecordData rdata = new DnsMXRecordData(
                5,
                "mail.example");

            int expected =
                2 + DnsDatagram.GetSerializeDomainNameLength("mail.example");

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