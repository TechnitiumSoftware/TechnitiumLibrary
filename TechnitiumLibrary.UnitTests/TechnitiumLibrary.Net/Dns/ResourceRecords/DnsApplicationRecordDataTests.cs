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
    public class DnsApplicationRecordDataTests
    {
        [TestMethod]
        public void Constructor_ValidInput_Succeeds()
        {
            DnsApplicationRecordData rdata = new DnsApplicationRecordData(
                "myApp",
                "com.example.MyClass",
                "{\"key\":\"value\"}");

            Assert.AreEqual("myApp", rdata.AppName);
            Assert.AreEqual("com.example.MyClass", rdata.ClassPath);
            Assert.AreEqual("{\"key\":\"value\"}", rdata.Data);
        }

        [TestMethod]
        public void Constructor_InvalidJson_Throws()
        {
            Assert.Throws<System.Text.Json.JsonException>(() =>
                new DnsApplicationRecordData(
                    "app",
                    "path",
                    "{invalid-json"));
        }

        [TestMethod]
        public void Equals_SameValues_AreEqual()
        {
            DnsApplicationRecordData a = new DnsApplicationRecordData("a", "b", "c");
            DnsApplicationRecordData b = new DnsApplicationRecordData("a", "b", "c");

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void Equals_DifferentData_AreNotEqual()
        {
            DnsApplicationRecordData a = new DnsApplicationRecordData("a", "b", "c");
            DnsApplicationRecordData b = new DnsApplicationRecordData("a", "b", "d");

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_ParsesAsUnknownRecord()
        {
            DnsResourceRecord original = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.NULL,
                DnsClass.IN,
                60,
                new DnsApplicationRecordData(
                    "app",
                    "class.path",
                    "payload"));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            DnsResourceRecord parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(DnsResourceRecordType.NULL, parsed.Type);
            Assert.IsInstanceOfType(parsed.RDATA, typeof(DnsUnknownRecordData));
        }

        [TestMethod]
        public void SerializeTo_ProducesValidJson()
        {
            DnsApplicationRecordData rdata = new DnsApplicationRecordData(
                "app",
                "path",
                "data");

            using MemoryStream ms = new();
            using System.Text.Json.Utf8JsonWriter writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            Assert.Contains("AppName", json);
            Assert.Contains("ClassPath", json);
            Assert.Contains("Data", json);
        }

        [TestMethod]
        public void UncompressedLength_MatchesWireLength()
        {
            DnsApplicationRecordData rdata = new DnsApplicationRecordData(
                "a",
                "b",
                "c");

            DnsResourceRecord rr = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.NULL,
                DnsClass.IN,
                60,
                rdata);

            byte[] wire = Serialize(rr);

            Assert.IsGreaterThan(0, rdata.UncompressedLength);
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