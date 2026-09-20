using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
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
            Assert.IsTrue(ep.Port > 0,
                "Default SocksProxyServer must bind an ephemeral port (port > 0).");
        }

        [TestMethod]
        public async Task Constructor_StartsListening_AndAcceptsTcpConnections()
        {
            using SocksProxyServer server = new SocksProxyServer();
            IPEndPoint ep = server.LocalEndPoint;

            using Socket client = new Socket(ep.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            await client.ConnectAsync(ep);

            Assert.IsTrue(client.Connected,
                "Client must be able to connect immediately since SocksProxyServer listens in the constructor.");
        }

        [TestMethod]
        public async Task Negotiation_InvalidVersion_MustBeRejected_Safely()
        {
            using SocksProxyServer server = new SocksProxyServer();
            IPEndPoint ep = server.LocalEndPoint;

            using Socket client = new Socket(ep.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            await client.ConnectAsync(ep);

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
                () => client.ConnectAsync(ep),
                "Disposed SocksProxyServer must not accept new TCP connections.");
        }
    }
}
