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
using System.Net;
using TechnitiumLibrary.Net;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net
{
    [TestClass]
    public sealed class NetUtilitiesTests
    {
        [TestMethod]
        public void IsPrivateIPv4_ShouldClassify_RFC1918_Correctly()
        {
            Assert.IsTrue(NetUtilities.IsPrivateIPv4(IPAddress.Parse("10.0.1.2")),
                "10.x must be private.");

            Assert.IsTrue(NetUtilities.IsPrivateIPv4(IPAddress.Parse("192.168.1.55")),
                "192.168.x must be private.");

            Assert.IsTrue(NetUtilities.IsPrivateIPv4(IPAddress.Parse("172.16.5.8")),
                "172.16/12 must be private.");

            Assert.IsFalse(NetUtilities.IsPrivateIPv4(IPAddress.Parse("11.1.1.1")),
                "Non-reserved space must not be treated private.");
        }

        [TestMethod]
        public void IsPrivateIPv4_ShouldRecognize_CarrierGradeNat()
        {
            Assert.IsTrue(NetUtilities.IsPrivateIPv4(IPAddress.Parse("100.64.10.10")),
                "100.64/10 must be private.");

            Assert.IsTrue(NetUtilities.IsPrivateIPv4(IPAddress.Parse("100.127.20.30")),
                "Upper CGNAT boundary must remain private.");

            Assert.IsFalse(NetUtilities.IsPrivateIPv4(IPAddress.Parse("100.128.10.10")),
                "Outside CGNAT must be classified public.");
        }

        [TestMethod]
        public void IsPrivateIPv4_ShouldReject_NonIPv4()
        {
            Assert.ThrowsExactly<ArgumentException>(
                () => NetUtilities.IsPrivateIPv4(IPAddress.IPv6Loopback),
                "Method must reject IPv6 input explicitly.");
        }

        [TestMethod]
        public void IsPrivateIP_ShouldMap_MappedIPv6_ToIPv4()
        {
            IPAddress mapped = IPAddress.Parse("::ffff:192.168.1.10");

            Assert.IsTrue(NetUtilities.IsPrivateIP(mapped),
                "Mapped IPv6 pointing to private IPv4 must classify private.");
        }

        [TestMethod]
        public void IsPrivateIP_ShouldTreat_NonGlobalIPv6_AsPrivate()
        {
            // fd00::/8 → Unique local
            IPAddress ula = IPAddress.Parse("fd00::1");

            Assert.IsTrue(NetUtilities.IsPrivateIP(ula),
                "Unique local must be private.");
        }

        [TestMethod]
        public void IsPrivateIP_ShouldThrow_WhenNullInput()
        {
            Assert.ThrowsExactly<NullReferenceException>(() =>
                NetUtilities.IsPrivateIP(null!),
                "Null input must be rejected immediately.");
        }

        [TestMethod]
        public void IsPrivateIP_ShouldNotThrow_ForIPv4()
        {
            IPAddress ip = IPAddress.Parse("192.168.1.10");
            Assert.IsTrue(NetUtilities.IsPrivateIP(ip));
        }

        [TestMethod]
        public void IsPrivateIP_ShouldNotThrow_ForIPv6()
        {
            IPAddress ip = IPAddress.Parse("2001:db8::1");
            Assert.IsFalse(NetUtilities.IsPrivateIP(ip));
        }

        [TestMethod]
        public void IsPublicIPv6_ShouldBeTrue_For2000Prefix()
        {
            IPAddress ip = IPAddress.Parse("2001:db8::1");

            Assert.IsTrue(NetUtilities.IsPublicIPv6(ip),
                "2000::/3 must be classified public.");
        }

        [TestMethod]
        public void IsPublicIPv6_ShouldBeFalse_WhenNotUnderGlobalRange()
        {
            IPAddress ip = IPAddress.Parse("fd00::1");

            Assert.IsFalse(NetUtilities.IsPublicIPv6(ip),
                "fd00:: is ULA and must not be public.");
        }

        [TestMethod]
        public void IsPublicIPv6_ShouldReject_IPv4()
        {
            Assert.ThrowsExactly<ArgumentException>(() =>
                NetUtilities.IsPublicIPv6(IPAddress.Parse("10.0.0.1")),
                "IPv6-only API must reject IPv4 explicitly.");
        }

        [TestMethod]
        public void NetworkInfoIPv4_ShouldComputeBroadcastCorrectly()
        {
            System.Net.NetworkInformation.NetworkInterface nic = FakeInterface.GetDummy();
            IPAddress local = IPAddress.Parse("192.168.5.10");
            IPAddress mask = IPAddress.Parse("255.255.255.0");

            NetworkInfo info = new NetworkInfo(nic, local, mask);

            Assert.AreEqual(IPAddress.Parse("192.168.5.255"), info.BroadcastIP,
                "Broadcast must OR mask inverse properly.");
        }

        [TestMethod]
        public void NetworkInfoIPv6_ShouldRejectIPv4()
        {
            System.Net.NetworkInformation.NetworkInterface nic = FakeInterface.GetDummy();

            Assert.ThrowsExactly<NotSupportedException>(() =>
                new NetworkInfo(nic, IPAddress.Parse("10.0.0.10")),
                "Constructor must reject non-IPv6 selectively.");
        }

        [TestMethod]
        public void NetworkInfoIPv4_ShouldRejectIPv6()
        {
            System.Net.NetworkInformation.NetworkInterface nic = FakeInterface.GetDummy();
            IPAddress local = IPAddress.Parse("fd00::1");
            IPAddress mask = IPAddress.Parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");

            Assert.ThrowsExactly<NotSupportedException>(() =>
                new NetworkInfo(nic, local, mask),
                "IPv4 constructor must reject IPv6 local address.");
        }

        [TestMethod]
        public void NetworkInfoEquality_ShouldBeTrue_WhenIPAndInterfaceMatch()
        {
            System.Net.NetworkInformation.NetworkInterface nic = FakeInterface.GetDummy();

            NetworkInfo a = new NetworkInfo(nic, IPAddress.IPv6Loopback);
            NetworkInfo b = new NetworkInfo(nic, IPAddress.IPv6Loopback);

            Assert.IsTrue(a.Equals(b),
                "Equality must hold across semantically identical instances.");
        }

        [TestMethod]
        public void NetworkInfoEquality_ShouldFail_OnDifferentIPs()
        {
            System.Net.NetworkInformation.NetworkInterface nic = FakeInterface.GetDummy();

            NetworkInfo a = new NetworkInfo(nic, IPAddress.IPv6Loopback);
            NetworkInfo b = new NetworkInfo(nic, IPAddress.Parse("2001:db8::1"));

            Assert.IsFalse(a.Equals(b),
                "Different addresses cannot compare equal.");
        }
    }

    internal static class FakeInterface
    {
        public static System.Net.NetworkInformation.NetworkInterface GetDummy()
        {
            // Fully stubbed mock via nested fake
            return new DummyNic();
        }

        private sealed class DummyNic : System.Net.NetworkInformation.NetworkInterface
        {
            public override string Description => "dummy";
            public override string Id => "dummy";
            public override bool IsReceiveOnly => false;
            public override string Name => "dummy0";

            public override System.Net.NetworkInformation.NetworkInterfaceType NetworkInterfaceType =>
                System.Net.NetworkInformation.NetworkInterfaceType.Loopback;

            public override System.Net.NetworkInformation.OperationalStatus OperationalStatus =>
                System.Net.NetworkInformation.OperationalStatus.Up;

            public override long Speed => 1;

            public override System.Net.NetworkInformation.IPInterfaceProperties GetIPProperties() =>
                throw new NotSupportedException();
        }
    }
}