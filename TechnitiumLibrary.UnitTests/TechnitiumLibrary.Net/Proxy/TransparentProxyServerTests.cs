using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public sealed class TransparentProxyServerTests
    {
        [TestMethod]
        public void Constructor_BindsLocalEndPoint_Immediately()
        {
            using TransparentProxyServer server =
                new TransparentProxyServer(
                    localEP: new IPEndPoint(IPAddress.Loopback, 0),
                    method: TransparentProxyServerMethod.Tunnel
                );

            IPEndPoint ep = server.LocalEndPoint;

            Assert.IsNotNull(ep,
                "LocalEndPoint must be available immediately after construction.");

            Assert.IsGreaterThan(0,
ep.Port, "TransparentProxyServer must bind to an ephemeral port when port=0 is specified.");
        }

        [TestMethod]
        public async Task Server_MustAcceptTcpConnections_WhileAlive()
        {
            using TransparentProxyServer server =
                new TransparentProxyServer(
                    localEP: new IPEndPoint(IPAddress.Loopback, 0),
                    method: TransparentProxyServerMethod.Tunnel
                );

            using Socket client =
                new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            await client.ConnectAsync(server.LocalEndPoint, TestContext.CancellationToken);

            Assert.IsTrue(client.Connected,
                "TransparentProxyServer must accept TCP connections while not disposed.");
        }

        [TestMethod]
        public async Task Dispose_MustStopAcceptingNewConnections()
        {
            TransparentProxyServer server =
                new TransparentProxyServer(
                    localEP: new IPEndPoint(IPAddress.Loopback, 0),
                    method: TransparentProxyServerMethod.Tunnel
                );

            IPEndPoint ep = server.LocalEndPoint;

            server.Dispose();
            server.Dispose(); // idempotency

            using Socket client =
                new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            await Assert.ThrowsExactlyAsync<SocketException>(
                () => client.ConnectAsync(ep, TestContext.CancellationToken).AsTask(),
                "Disposed TransparentProxyServer must not accept new TCP connections.");
        }

        [TestMethod]
        public void Constructor_DNAT_OnNonUnix_MustThrowNotSupportedException()
        {
            Assert.ThrowsExactly<NotSupportedException>(
                () => new TransparentProxyServer(
                    localEP: new IPEndPoint(IPAddress.Loopback, 0),
                    method: TransparentProxyServerMethod.DNAT
                ),
                "DNAT mode must throw on non-Unix platforms.");
        }

        [TestMethod]
        [OSCondition(OperatingSystems.Linux | OperatingSystems.OSX | OperatingSystems.FreeBSD)]
        public void Constructor_DNAT_WithIPv6_MustThrowNotSupportedException()
        {
            Assert.ThrowsExactly<NotSupportedException>(
                () => new TransparentProxyServer(
                    localEP: new IPEndPoint(IPAddress.IPv6Loopback, 0),
                    method: TransparentProxyServerMethod.DNAT
                ),
                "DNAT mode must reject non-IPv4 local endpoints.");
        }

        public TestContext TestContext { get; set; }
    }
}