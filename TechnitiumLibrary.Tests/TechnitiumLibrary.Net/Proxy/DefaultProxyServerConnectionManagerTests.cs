using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public class DefaultProxyServerConnectionManagerTests
    {
        public TestContext TestContext { get; set; }

        private static TcpListener StartLoopbackListener(AddressFamily family, out IPEndPoint ep)
        {
            IPAddress addr = family == AddressFamily.InterNetwork ?
                IPAddress.Loopback :
                IPAddress.IPv6Loopback;

            var listener = new TcpListener(addr, 0);
            listener.Start();
            ep = (IPEndPoint)listener.LocalEndpoint;
            return listener;
        }

        [TestMethod]
        public async Task ConnectAsync_WithIPEndPoint_ConnectsSuccessfully()
        {
            TcpListener listener = StartLoopbackListener(AddressFamily.InterNetwork, out IPEndPoint serverEp);

            var manager = new DefaultProxyServerConnectionManager();

            using Socket client = await manager.ConnectAsync(serverEp, TestContext.CancellationToken);

            Assert.IsTrue(client.Connected, "Socket must connect successfully to loopback listener.");

            using Socket server = await listener.AcceptSocketAsync(TestContext.CancellationToken);
            Assert.IsTrue(server.Connected, "Listener must accept connection.");

            Assert.IsTrue(client.NoDelay, "ConnectAsync must set NoDelay=true.");

            client.Dispose();
            listener.Stop();
        }

        [TestMethod]
        public async Task ConnectAsync_WithDnsEndPoint_ExplicitIPv4_ResolvesAndConnects()
        {
            TcpListener listener = StartLoopbackListener(AddressFamily.InterNetwork, out IPEndPoint serverEp);

            var manager = new DefaultProxyServerConnectionManager();

            // DnsEndPoint → IPv4 resolution is supported when family is explicitly InterNetwork.
            var dns = new DnsEndPoint("localhost", serverEp.Port, AddressFamily.InterNetwork);

            using Socket client = await manager.ConnectAsync(dns, TestContext.CancellationToken);

            Assert.IsTrue(client.Connected);

            using Socket server = await listener.AcceptSocketAsync(TestContext.CancellationToken);
            Assert.IsTrue(server.Connected);

            listener.Stop();
        }

        [TestMethod]
        public async Task ConnectAsync_WithDnsEndPoint_ExplicitIPv6_ResolvesAndConnects_IfIPv6Available()
        {
            // Skip test on machines without IPv6 enabled.
            if (!Socket.OSSupportsIPv6)
            {
                Assert.Inconclusive("IPv6 not supported on this system.");
                return;
            }

            TcpListener listener = StartLoopbackListener(AddressFamily.InterNetworkV6, out IPEndPoint serverEp);

            var manager = new DefaultProxyServerConnectionManager();

            var dns = new DnsEndPoint("localhost", serverEp.Port, AddressFamily.InterNetworkV6);

            using Socket client = await manager.ConnectAsync(dns, TestContext.CancellationToken);

            Assert.IsTrue(client.Connected);

            using Socket server = await listener.AcceptSocketAsync(TestContext.CancellationToken);
            Assert.IsTrue(server.Connected);

            listener.Stop();
        }

        [TestMethod]
        public async Task ConnectAsync_WithDnsEndPoint_AddressFamilyMismatch_ThrowsSocketException()
        {
            TcpListener listener = StartLoopbackListener(AddressFamily.InterNetwork, out IPEndPoint serverEp);

            var manager = new DefaultProxyServerConnectionManager();

            // Force IPv6 resolution against an IPv4 listener → mismatch.
            var dns = new DnsEndPoint("localhost", serverEp.Port, AddressFamily.InterNetworkV6);

            await Assert.ThrowsExactlyAsync<SocketException>(
                () => manager.ConnectAsync(dns, TestContext.CancellationToken));

            listener.Stop();
        }

        [TestMethod]
        public async Task ConnectAsync_UnspecifiedAddressFamilyDns_ThrowsNotSupportedException()
        {
            TcpListener listener = StartLoopbackListener(AddressFamily.InterNetwork, out IPEndPoint serverEp);

            var manager = new DefaultProxyServerConnectionManager();

            var dns = new DnsEndPoint("localhost", serverEp.Port, AddressFamily.Unspecified);

            // Implementation explicitly throws NotSupportedException through GetIPEndPointAsync
            await Assert.ThrowsExactlyAsync<NotSupportedException>(
                () => manager.ConnectAsync(dns, TestContext.CancellationToken));

            listener.Stop();
        }

        [TestMethod]
        public async Task ConnectAsync_AddressFamilyMismatchWithIPEndPoint_ThrowsSocketException()
        {
            // Listener is IPv4
            TcpListener listener = StartLoopbackListener(AddressFamily.InterNetwork, out IPEndPoint serverEp);

            var manager = new DefaultProxyServerConnectionManager();

            // Try to connect using IPv6 to IPv4 listener
            var ipv6Target = new IPEndPoint(IPAddress.IPv6Loopback, serverEp.Port);

            await Assert.ThrowsExactlyAsync<SocketException>(
                () => manager.ConnectAsync(ipv6Target, TestContext.CancellationToken));

            listener.Stop();
        }
    }
}
