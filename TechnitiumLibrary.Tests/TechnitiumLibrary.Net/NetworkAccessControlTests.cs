using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Net;
using TechnitiumLibrary.Net;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net
{
    [TestClass]
    public sealed class NetworkAccessControlTests
    {
        [TestMethod]
        public void Parse_ShouldParseAllowRule()
        {
            NetworkAccessControl nac = NetworkAccessControl.Parse("192.168.1.0/24");

            Assert.IsFalse(nac.Deny);
            Assert.AreEqual("192.168.1.0/24", nac.ToString());
        }

        [TestMethod]
        public void Parse_ShouldParseDenyRule()
        {
            NetworkAccessControl nac = NetworkAccessControl.Parse("!10.0.0.0/8");

            Assert.IsTrue(nac.Deny);
            Assert.AreEqual("!10.0.0.0/8", nac.ToString());
        }

        [TestMethod]
        public void Parse_ShouldThrow_OnInvalidAddress()
        {
            Assert.ThrowsExactly<FormatException>(
                () => NetworkAccessControl.Parse("!!bad"),
                "Invalid rules must trigger FormatException.");
        }

        [TestMethod]
        public void TryParse_ShouldReturnFalse_OnMalformed()
        {
            bool ok = NetworkAccessControl.TryParse("invalid", out NetworkAccessControl? nac);

            Assert.IsFalse(ok);
            Assert.IsNull(nac);
        }

        [TestMethod]
        public void TryMatch_ShouldReturnTrueOnMatch()
        {
            NetworkAccessControl nac = new NetworkAccessControl(IPAddress.Parse("192.168.1.0"), 24);

            bool matched = nac.TryMatch(IPAddress.Parse("192.168.1.42"), out bool allowed);

            Assert.IsTrue(matched, "Prefix match expected.");
            Assert.IsTrue(allowed, "Positive rule must allow.");
        }

        [TestMethod]
        public void TryMatch_ShouldReturnFalseWhenNotInNetwork()
        {
            NetworkAccessControl nac = new NetworkAccessControl(IPAddress.Parse("10.0.0.0"), 8);

            bool matched = nac.TryMatch(IPAddress.Parse("11.0.0.1"), out bool allowed);

            Assert.IsFalse(matched);
            Assert.IsFalse(allowed);
        }

        [TestMethod]
        public void TryMatch_ShouldHonorNegation()
        {
            NetworkAccessControl nac = new NetworkAccessControl(IPAddress.Parse("10.0.0.0"), 8, deny: true);

            bool matched = nac.TryMatch(IPAddress.Parse("10.0.55.77"), out bool allowed);

            Assert.IsTrue(matched);
            Assert.IsFalse(allowed, "Deny rule must return allowed=false.");
        }

        [TestMethod]
        public void IsAddressAllowed_ShouldReturnFirstMatchingResult()
        {
            NetworkAccessControl[] acl = new[]
            {
                new NetworkAccessControl(IPAddress.Parse("10.0.1.0"), 24, deny:true), // deny first
                new NetworkAccessControl(IPAddress.Parse("10.0.0.0"), 8), // allow
            };

            bool allowed = NetworkAccessControl.IsAddressAllowed(IPAddress.Parse("10.0.1.42"), acl);

            Assert.IsFalse(allowed, "First matching entry (deny) must determine result.");
        }


        [TestMethod]
        public void IsAddressAllowed_ShouldReturnLoopbackWhenNoMatch()
        {
            bool allowed = NetworkAccessControl.IsAddressAllowed(
                IPAddress.Loopback,
                acl: null,
                allowLoopbackWhenNoMatch: true);

            Assert.IsTrue(allowed);
        }

        [TestMethod]
        public void IsAddressAllowed_ShouldReturnFalseWithoutMatchAndNoLoopbackMode()
        {
            bool allowed = NetworkAccessControl.IsAddressAllowed(
                IPAddress.Parse("5.5.5.5"),
                new NetworkAccessControl[0],
                allowLoopbackWhenNoMatch: false);

            Assert.IsFalse(allowed);
        }

        [TestMethod]
        public void WriteTo_ShouldRoundtrip()
        {
            NetworkAccessControl original = new NetworkAccessControl(IPAddress.Parse("10.2.3.0"), 24, deny: true);

            using MemoryStream ms = new MemoryStream();
            using BinaryWriter bw = new BinaryWriter(ms);

            original.WriteTo(bw);
            bw.Flush();
            ms.Position = 0;

            using BinaryReader br = new BinaryReader(ms);
            NetworkAccessControl read = NetworkAccessControl.ReadFrom(br);

            Assert.IsTrue(original.Equals(read), "Binary round trip must preserve rule.");
            Assert.AreEqual(original.ToString(), read.ToString());
        }

        [TestMethod]
        public void Equals_ShouldReturnTrue_WhenEquivalent()
        {
            NetworkAccessControl a = new NetworkAccessControl(IPAddress.Parse("10.0.0.0"), 8, deny: true);
            NetworkAccessControl b = new NetworkAccessControl(IPAddress.Parse("10.0.0.0"), 8, deny: true);

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void Equals_ShouldReturnFalse_WhenDifferentAddress()
        {
            NetworkAccessControl a = new NetworkAccessControl(IPAddress.Parse("10.0.0.0"), 8);
            NetworkAccessControl b = new NetworkAccessControl(IPAddress.Parse("10.1.0.0"), 16);

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void ToString_ShouldRenderCorrectly()
        {
            NetworkAccessControl allow = new NetworkAccessControl(IPAddress.Parse("192.168.0.0"), 16);
            NetworkAccessControl deny = new NetworkAccessControl(IPAddress.Parse("100.64.0.0"), 10, deny: true);

            Assert.AreEqual("192.168.0.0/16", allow.ToString());
            Assert.AreEqual("!100.64.0.0/10", deny.ToString());
        }
    }
}
