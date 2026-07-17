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
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public sealed class SocksProxyServerTests
    {
        [TestMethod]
        public void Constructor_Default_BindsLoopbackAndEphemeralPort()
        {
            using SocksProxyServer server = new SocksProxyServer();

            IPEndPoint ep = server.LocalEndPoint;

            Assert.IsNotNull(ep, "LocalEndPoint must be non-null after construction.");
            Assert.IsTrue(IPAddress.IsLoopback(ep.Address),
                "Default SocksProxyServer must bind only to loopback to avoid exposing an open proxy.");
            Assert.IsGreaterThan(0,
ep.Port, "Default SocksProxyServer must bind an ephemeral port (port > 0).");
        }

        [TestMethod]
        public async Task Constructor_StartsListening_AndAcceptsTcpConnections()
        {
            using SocksProxyServer server = new SocksProxyServer();
            IPEndPoint ep = server.LocalEndPoint;

            using Socket client = new Socket(ep.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            await client.ConnectAsync(ep, TestContext.CancellationToken);

            Assert.IsTrue(client.Connected,
                "Client must be able to connect immediately since SocksProxyServer listens in the constructor.");
        }

        [TestMethod]
        public async Task Negotiation_InvalidVersion_MustBeRejected_Safely()
        {
            using SocksProxyServer server = new SocksProxyServer();
            IPEndPoint ep = server.LocalEndPoint;

            using Socket client = new Socket(ep.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            await client.ConnectAsync(ep, TestContext.CancellationToken);

            // Invalid SOCKS greeting (version 0x04)
            byte[] invalidGreeting = new byte[] { 0x04, 0x01, 0x00 };
            await client.SendAsync(invalidGreeting, SocketFlags.None);

            byte[] buffer = new byte[2];

            try
            {
                int received = await client.ReceiveAsync(buffer, SocketFlags.None);

                // If bytes are received, connection must not proceed further
                Assert.IsTrue(
                    received == 0 || received == 2,
                    "Server may either close immediately or send a minimal rejection response."
                );
            }
            catch (SocketException)
            {
                // Also acceptable: immediate connection reset
            }
        }

        [TestMethod]
        public async Task Dispose_MustStopAcceptingNewConnections_AndBeIdempotent()
        {
            SocksProxyServer server = new SocksProxyServer();
            IPEndPoint ep = server.LocalEndPoint;

            server.Dispose();
            server.Dispose();

            using Socket client = new Socket(ep.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            await Assert.ThrowsExactlyAsync<SocketException>(
                () => client.ConnectAsync(ep, TestContext.CancellationToken).AsTask(),
                "Disposed SocksProxyServer must not accept new TCP connections.");
        }

        public TestContext TestContext { get; set; }
    }
}