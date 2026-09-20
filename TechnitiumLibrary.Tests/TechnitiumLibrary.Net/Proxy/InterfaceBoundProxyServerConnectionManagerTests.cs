using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public class InterfaceBoundProxyServerConnectionManagerTests
    {
        public TestContext TestContext { get; set; }

        private static TcpListener StartLoopbackListener(AddressFamily family, out IPEndPoint localEndPoint)
        {
            IPAddress address = family switch
            {
                AddressFamily.InterNetwork => IPAddress.Loopback,
                AddressFamily.InterNetworkV6 => IPAddress.IPv6Loopback,
                _ => throw new NotSupportedException("Only IPv4 and IPv6 are supported in test helper.")
            };

            TcpListener listener = new TcpListener(address, 0);
            listener.Start();

            Assert.IsNotNull(listener.LocalEndpoint, "Listener.LocalEndpoint must be initialized after Start().");
            Assert.IsInstanceOfType<IPEndPoint>(
                listener.LocalEndpoint,
                "Listener.LocalEndpoint must be an IPEndPoint instance.");

            // Null-forgiving operator to satisfy nullable analysis; we already asserted non-null + type.
            localEndPoint = (IPEndPoint)listener.LocalEndpoint!;
            return listener;
        }

        [TestMethod]
        public void Constructor_ExposesBindAddress()
        {
            IPAddress bindAddress = IPAddress.Loopback;

            InterfaceBoundProxyServerConnectionManager manager = new InterfaceBoundProxyServerConnectionManager(bindAddress);

            Assert.AreEqual(
                bindAddress,
                manager.BindAddress,
                "BindAddress property must reflect the constructor-provided bind address.");
        }

        [TestMethod]
        public async Task ConnectAsync_WithMatchingAddressFamily_BindsAndConnectsFromBindAddress()
        {
            TcpListener listener = StartLoopbackListener(AddressFamily.InterNetwork, out IPEndPoint serverEndPoint);

            InterfaceBoundProxyServerConnectionManager manager = new InterfaceBoundProxyServerConnectionManager(IPAddress.Loopback);

            Socket clientSocket = await manager.ConnectAsync(serverEndPoint, TestContext.CancellationToken);

            using Socket serverSocket = await listener.AcceptSocketAsync(TestContext.CancellationToken);

            Assert.IsTrue(clientSocket.Connected, "Client socket must be connected when address families match.");
            Assert.IsTrue(serverSocket.Connected, "Server-side accepted socket must be connected.");

            Assert.IsNotNull(clientSocket.LocalEndPoint, "Client LocalEndPoint must be set after a successful connect.");
            Assert.IsInstanceOfType<IPEndPoint>(
                clientSocket.LocalEndPoint,
                "Client LocalEndPoint must be an IPEndPoint.");

            // Null-forgiving: guarded by IsNotNull + IsInstanceOfType above.
            IPEndPoint local = (IPEndPoint)clientSocket.LocalEndPoint!;
            Assert.AreEqual(
                IPAddress.Loopback,
                local.Address,
                "Client must bind to the configured bind address for outbound connections.");

            clientSocket.Dispose();
            listener.Stop();
        }

        [TestMethod]
        public async Task ConnectAsync_WithUnspecifiedDnsEndPoint_ThrowsNotSupported()
        {
            TcpListener listener = StartLoopbackListener(AddressFamily.InterNetwork, out IPEndPoint serverEndPoint);

            InterfaceBoundProxyServerConnectionManager manager = new InterfaceBoundProxyServerConnectionManager(IPAddress.Loopback);

            DnsEndPoint dnsEp = new DnsEndPoint("localhost", serverEndPoint.Port, AddressFamily.Unspecified);

            await Assert.ThrowsExactlyAsync<NotSupportedException>(
                () => manager.ConnectAsync(dnsEp, TestContext.CancellationToken),
                "Unspecified DnsEndPoint with ambiguous resolution must fail with NotSupportedException when bound to a specific address family.");

            listener.Stop();
        }

        [TestMethod]
        public async Task ConnectAsync_WithMismatchedFamily_ThrowsNetworkUnreachable()
        {
            // Bind manager to IPv4 but use IPv6 endpoint.
            InterfaceBoundProxyServerConnectionManager manager = new InterfaceBoundProxyServerConnectionManager(IPAddress.Loopback);
            IPEndPoint remote = new IPEndPoint(IPAddress.IPv6Loopback, 443);

            SocketException ex = await Assert.ThrowsExactlyAsync<SocketException>(
                () => manager.ConnectAsync(remote, TestContext.CancellationToken),
                "ConnectAsync must throw SocketException when the remote endpoint family does not match the bind address family.");

            Assert.AreEqual(
                SocketError.NetworkUnreachable,
                ex.SocketErrorCode,
                "Mismatched family must surface NetworkUnreachable to the caller.");
        }

        [TestMethod]
        public async Task GetBindHandlerAsync_WithMatchingFamily_ReturnsHandler()
        {
            InterfaceBoundProxyServerConnectionManager manager = new InterfaceBoundProxyServerConnectionManager(IPAddress.Loopback);

            IProxyServerBindHandler handler = await manager.GetBindHandlerAsync(AddressFamily.InterNetwork);

            Assert.IsNotNull(handler, "GetBindHandlerAsync must return a non-null handler for matching address family.");

            if (handler is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }

        [TestMethod]
        public async Task GetBindHandlerAsync_WithMismatchedFamily_ThrowsNetworkUnreachable()
        {
            InterfaceBoundProxyServerConnectionManager manager = new InterfaceBoundProxyServerConnectionManager(IPAddress.Loopback);

            SocketException ex = await Assert.ThrowsExactlyAsync<SocketException>(
                () => manager.GetBindHandlerAsync(AddressFamily.InterNetworkV6),
                "GetBindHandlerAsync must fail when the requested family does not match the bind address family.");

            Assert.AreEqual(
                SocketError.NetworkUnreachable,
                ex.SocketErrorCode,
                "Bind handler lookup must surface NetworkUnreachable for mismatched family.");
        }

        [TestMethod]
        public async Task GetUdpAssociateHandlerAsync_WithMatchingFamily_ReturnsHandler()
        {
            InterfaceBoundProxyServerConnectionManager manager = new InterfaceBoundProxyServerConnectionManager(IPAddress.Loopback);
            IPEndPoint localEp = new IPEndPoint(IPAddress.Loopback, 0);

            IProxyServerUdpAssociateHandler handler = await manager.GetUdpAssociateHandlerAsync(localEp);

            Assert.IsNotNull(handler, "GetUdpAssociateHandlerAsync must return a non-null handler for matching family.");

            if (handler is IDisposable disposable)
                disposable.Dispose();
        }

        [TestMethod]
        public async Task GetUdpAssociateHandlerAsync_WithMismatchedFamily_ThrowsNetworkUnreachable()
        {
            InterfaceBoundProxyServerConnectionManager manager = new InterfaceBoundProxyServerConnectionManager(IPAddress.Loopback);
            IPEndPoint localEp = new IPEndPoint(IPAddress.IPv6Loopback, 0);

            SocketException ex = await Assert.ThrowsExactlyAsync<SocketException>(
                () => manager.GetUdpAssociateHandlerAsync(localEp),
                "UDP handler lookup must fail when the endpoint family does not match the bind address.");

            Assert.AreEqual(
                SocketError.NetworkUnreachable,
                ex.SocketErrorCode,
                "UDP handler lookup must surface NetworkUnreachable for mismatched family.");
        }
    }
}
