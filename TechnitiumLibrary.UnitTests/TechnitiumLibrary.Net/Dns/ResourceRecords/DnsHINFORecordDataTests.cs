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
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsHINFORecordDataTests
    {
        [TestMethod]
        public void Constructor_ValidInput_Succeeds()
        {
            DnsHINFORecordData rdata = new DnsHINFORecordData(
                cpu: "INTEL",
                os: "LINUX");

            Assert.AreEqual("INTEL", rdata.CPU);
            Assert.AreEqual("LINUX", rdata.OS);
        }

        [TestMethod]
        public void Equals_SameValues_AreEqual()
        {
            DnsHINFORecordData a = new DnsHINFORecordData("AMD64", "WINDOWS");
            DnsHINFORecordData b = new DnsHINFORecordData("AMD64", "WINDOWS");

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void Equals_DifferentCpu_IsFalse()
        {
            DnsHINFORecordData a = new DnsHINFORecordData("INTEL", "LINUX");
            DnsHINFORecordData b = new DnsHINFORecordData("ARM", "LINUX");

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void Equals_DifferentOs_IsFalse()
        {
            DnsHINFORecordData a = new DnsHINFORecordData("INTEL", "LINUX");
            DnsHINFORecordData b = new DnsHINFORecordData("INTEL", "BSD");

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            DnsResourceRecord original = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.HINFO,
                DnsClass.IN,
                3600,
                new DnsHINFORecordData("INTEL", "LINUX"));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            DnsResourceRecord parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            DnsHINFORecordData rdata = new DnsHINFORecordData("ARM", "IOS");

            using MemoryStream ms = new();
            using System.Text.Json.Utf8JsonWriter writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            Assert.Contains("CPU", json);
            Assert.Contains("ARM", json);
            Assert.Contains("OS", json);
            Assert.Contains("IOS", json);
        }

        [TestMethod]
        public void UncompressedLength_MatchesExpectedFormula()
        {
            DnsHINFORecordData rdata = new DnsHINFORecordData("CPU", "OS");

            int expected =
                1 + "CPU".Length +
                1 + "OS".Length;

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