using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public class LoadBalancingProxyServerConnectionManagerTests
    {
        public TestContext TestContext { get; set; }

        private static readonly EndPoint DummyConnectivityEndPoint =
            new IPEndPoint(IPAddress.Loopback, 80);

        #region tests – ConnectAsync

        [TestMethod]
        public async Task ConnectAsync_WithIPv4Endpoint_UsesIPv4ConnectionManager()
        {
            var ipv4Manager = new FakeConnectionManager(AddressFamily.InterNetwork);
            var ipv6Manager = new FakeConnectionManager(AddressFamily.InterNetworkV6);

            using var manager = new LoadBalancingProxyServerConnectionManager(
                new[] { ipv4Manager },
                new[] { ipv6Manager },
                new[] { DummyConnectivityEndPoint });

            var target = new IPEndPoint(IPAddress.Loopback, 12345);

            using Socket socket = await manager.ConnectAsync(target, TestContext.CancellationToken);

            Assert.AreEqual(
                1,
                ipv4Manager.ConnectCallCount,
                "IPv4 endpoint must be delegated to an IPv4 connection manager.");

            Assert.AreEqual(
                0,
                ipv6Manager.ConnectCallCount,
                "IPv6 connection manager must not be used for IPv4 endpoints.");

            Assert.AreEqual(
                target,
                ipv4Manager.LastRemoteEndPoint,
                "IPv4 manager must see the exact remote endpoint passed to ConnectAsync.");

            Assert.AreEqual(
                AddressFamily.InterNetwork,
                socket.AddressFamily,
                "Returned socket family must match the selected IPv4 manager.");
        }

        [TestMethod]
        public async Task ConnectAsync_WithIPv6Endpoint_UsesIPv6ConnectionManager_IfSupported()
        {
            if (!Socket.OSSupportsIPv6)
            {
                Assert.Inconclusive("IPv6 is not supported on this system.");
                return;
            }

            var ipv4Manager = new FakeConnectionManager(AddressFamily.InterNetwork);
            var ipv6Manager = new FakeConnectionManager(AddressFamily.InterNetworkV6);

            using var manager = new LoadBalancingProxyServerConnectionManager(
                new[] { ipv4Manager },
                new[] { ipv6Manager },
                new[] { DummyConnectivityEndPoint });

            var target = new IPEndPoint(IPAddress.IPv6Loopback, 12345);

            using Socket socket = await manager.ConnectAsync(target, TestContext.CancellationToken);

            Assert.AreEqual(
                0,
                ipv4Manager.ConnectCallCount,
                "IPv4 connection manager must not be used for IPv6 endpoints.");

            Assert.AreEqual(
                1,
                ipv6Manager.ConnectCallCount,
                "IPv6 endpoint must be delegated to an IPv6 connection manager.");

            Assert.AreEqual(
                target,
                ipv6Manager.LastRemoteEndPoint,
                "IPv6 manager must see the exact remote endpoint passed to ConnectAsync.");

            Assert.AreEqual(
                AddressFamily.InterNetworkV6,
                socket.AddressFamily,
                "Returned socket family must match the selected IPv6 manager.");
        }

        [TestMethod]
        public async Task ConnectAsync_WithUnspecifiedDomain_BothFamiliesAvailable_UsesOneFamilyConsistently()
        {
            var ipv4Manager = new FakeConnectionManager(AddressFamily.InterNetwork);
            var ipv6Manager = new FakeConnectionManager(AddressFamily.InterNetworkV6);

            using var manager = new LoadBalancingProxyServerConnectionManager(
                new[] { ipv4Manager },
                new[] { ipv6Manager },
                new[] { DummyConnectivityEndPoint });

            // DomainEndPoint with AddressFamily.Unspecified – will be resolved by GetIPEndPointAsync.
            var domain = new DomainEndPoint("localhost", 443);

            using Socket socket = await manager.ConnectAsync(domain, TestContext.CancellationToken);

            int totalCalls = ipv4Manager.ConnectCallCount + ipv6Manager.ConnectCallCount;

            Assert.AreEqual(
                1,
                totalCalls,
                "Exactly one underlying connection manager must be used per ConnectAsync call.");

            FakeConnectionManager chosen =
                ipv4Manager.ConnectCallCount == 1 ? ipv4Manager : ipv6Manager;

            Assert.IsNotNull(
                chosen.LastRemoteEndPoint,
                "Chosen manager must receive a resolved IPEndPoint.");

            Assert.IsInstanceOfType(
                chosen.LastRemoteEndPoint,
                typeof(IPEndPoint),
                "Unspecified domain endpoint must be resolved to an IPEndPoint.");

            var resolved = (IPEndPoint)chosen.LastRemoteEndPoint!;
            Assert.AreEqual(
                chosen.Family,
                resolved.AddressFamily,
                "Resolved endpoint family must match the chosen manager family.");

            Assert.AreEqual(
                chosen.Family,
                socket.AddressFamily,
                "Returned socket family must match the chosen manager family.");
        }

        [TestMethod]
        public async Task ConnectAsync_WithUnspecifiedDomain_OnlyIPv4Available_ResolvesToIPv4()
        {
            var ipv4Manager = new FakeConnectionManager(AddressFamily.InterNetwork);

            using var manager = new LoadBalancingProxyServerConnectionManager(
                new[] { ipv4Manager },
                Array.Empty<IProxyServerConnectionManager>(),
                new[] { DummyConnectivityEndPoint });

            var domain = new DomainEndPoint("localhost", 80);

            using Socket socket = await manager.ConnectAsync(domain, TestContext.CancellationToken);

            Assert.AreEqual(
                1,
                ipv4Manager.ConnectCallCount,
                "With only IPv4 managers available, ConnectAsync must route to IPv4.");

            Assert.IsInstanceOfType(
                ipv4Manager.LastRemoteEndPoint,
                typeof(IPEndPoint),
                "DomainEndPoint must be resolved to an IPv4 IPEndPoint when only IPv4 is available.");

            var resolved = (IPEndPoint)ipv4Manager.LastRemoteEndPoint!;
            Assert.AreEqual(
                AddressFamily.InterNetwork,
                resolved.AddressFamily,
                "Resolved endpoint must be IPv4 when only IPv4 managers are available.");

            Assert.AreEqual(
                AddressFamily.InterNetwork,
                socket.AddressFamily,
                "Returned socket family must be IPv4 when only IPv4 managers are available.");
        }

        [TestMethod]
        public async Task ConnectAsync_WithUnspecifiedDomain_OnlyIPv6Available_ResolvesToIPv6_IfSupported()
        {
            if (!Socket.OSSupportsIPv6)
            {
                Assert.Inconclusive("IPv6 is not supported on this system.");
                return;
            }

            var ipv6Manager = new FakeConnectionManager(AddressFamily.InterNetworkV6);

            using var manager = new LoadBalancingProxyServerConnectionManager(
                Array.Empty<IProxyServerConnectionManager>(),
                new[] { ipv6Manager },
                new[] { DummyConnectivityEndPoint });

            var domain = new DomainEndPoint("localhost", 80);

            using Socket socket = await manager.ConnectAsync(domain, TestContext.CancellationToken);

            Assert.AreEqual(
                1,
                ipv6Manager.ConnectCallCount,
                "With only IPv6 managers available, ConnectAsync must route to IPv6.");

            Assert.IsInstanceOfType(
                ipv6Manager.LastRemoteEndPoint,
                typeof(IPEndPoint),
                "DomainEndPoint must be resolved to an IPv6 IPEndPoint when only IPv6 is available.");

            var resolved = (IPEndPoint)ipv6Manager.LastRemoteEndPoint!;
            Assert.AreEqual(
                AddressFamily.InterNetworkV6,
                resolved.AddressFamily,
                "Resolved endpoint must be IPv6 when only IPv6 managers are available.");

            Assert.AreEqual(
                AddressFamily.InterNetworkV6,
                socket.AddressFamily,
                "Returned socket family must be IPv6 when only IPv6 managers are available.");
        }

        [TestMethod]
        public async Task ConnectAsync_WithUnspecifiedDomain_NoWorkingManagers_ThrowsNetworkUnreachable()
        {
            using var manager = new LoadBalancingProxyServerConnectionManager(
                Array.Empty<IProxyServerConnectionManager>(),
                Array.Empty<IProxyServerConnectionManager>(),
                new[] { DummyConnectivityEndPoint });

            var domain = new DomainEndPoint("localhost", 443);

            SocketException ex = await Assert.ThrowsExactlyAsync<SocketException>(
                () => manager.ConnectAsync(domain, TestContext.CancellationToken),
                "When no working managers exist, ConnectAsync must fail with SocketError.NetworkUnreachable.");

            Assert.AreEqual(
                SocketError.NetworkUnreachable,
                ex.SocketErrorCode,
                "ConnectAsync must surface NetworkUnreachable when no family is available.");
        }

        [TestMethod]
        public async Task ConnectAsync_WithRedundancyOnly_AlwaysUsesFirstWorkingManager()
        {
            var primary = new FakeConnectionManager(AddressFamily.InterNetwork);
            var secondary = new FakeConnectionManager(AddressFamily.InterNetwork);

            using var manager = new LoadBalancingProxyServerConnectionManager(
                new[] { primary, secondary },
                Array.Empty<IProxyServerConnectionManager>(),
                new[] { DummyConnectivityEndPoint },
                redundancyOnly: true);

            var target = new IPEndPoint(IPAddress.Loopback, 8080);

            const int attempts = 5;

            for (int i = 0; i < attempts; i++)
            {
                using Socket socket = await manager.ConnectAsync(target, TestContext.CancellationToken);
            }

            Assert.AreEqual(
                attempts,
                primary.ConnectCallCount,
                "In redundancy-only mode, the first working manager must handle all IPv4 connections.");

            Assert.AreEqual(
                0,
                secondary.ConnectCallCount,
                "In redundancy-only mode, secondary managers must not be used while primary is healthy.");
        }

        #endregion

        #region tests – Bind and UDP delegation

        [TestMethod]
        public async Task GetBindHandlerAsync_DelegatesToCorrectFamilyManager()
        {
            var v4Primary = new FakeConnectionManager(AddressFamily.InterNetwork);
            var v4Secondary = new FakeConnectionManager(AddressFamily.InterNetwork);

            using var manager = new LoadBalancingProxyServerConnectionManager(
                new[] { v4Primary, v4Secondary },
                Array.Empty<IProxyServerConnectionManager>(),
                new[] { DummyConnectivityEndPoint });

            IProxyServerBindHandler handler = await manager.GetBindHandlerAsync(AddressFamily.InterNetwork);

            Assert.IsTrue(
                ReferenceEquals(handler, v4Primary.BindHandler) ||
                ReferenceEquals(handler, v4Secondary.BindHandler),
                "Bind handler must be obtained from one of the IPv4 managers.");

            int totalBindCalls = v4Primary.BindCallCount + v4Secondary.BindCallCount;

            Assert.AreEqual(
                1,
                totalBindCalls,
                "Load balancer must delegate a single bind request to exactly one manager.");
        }

        [TestMethod]
        public async Task GetBindHandlerAsync_NoManagersForFamily_ThrowsNetworkUnreachable()
        {
            using var manager = new LoadBalancingProxyServerConnectionManager(
                Array.Empty<IProxyServerConnectionManager>(),
                Array.Empty<IProxyServerConnectionManager>(),
                new[] { DummyConnectivityEndPoint });

            SocketException ex = await Assert.ThrowsExactlyAsync<SocketException>(
                () => manager.GetBindHandlerAsync(AddressFamily.InterNetwork),
                "GetBindHandlerAsync must fail with NetworkUnreachable when no managers exist for the family.");

            Assert.AreEqual(
                SocketError.NetworkUnreachable,
                ex.SocketErrorCode,
                "Bind handler lookup must surface NetworkUnreachable when no managers exist.");
        }

        [TestMethod]
        public async Task GetUdpAssociateHandlerAsync_DelegatesToCorrectFamilyManager()
        {
            var v4Manager = new FakeConnectionManager(AddressFamily.InterNetwork);

            using var manager = new LoadBalancingProxyServerConnectionManager(
                new[] { v4Manager },
                Array.Empty<IProxyServerConnectionManager>(),
                new[] { DummyConnectivityEndPoint });

            var localEp = new IPEndPoint(IPAddress.Loopback, 0);

            IProxyServerUdpAssociateHandler handler =
                await manager.GetUdpAssociateHandlerAsync(localEp);

            Assert.IsTrue(
                ReferenceEquals(handler, v4Manager.UdpHandler),
                "UDP associate handler must be obtained from the matching IPv4 manager.");

            Assert.AreEqual(
                1,
                v4Manager.UdpCallCount,
                "Exactly one UDP associate request must be delegated to the manager.");
        }

        [TestMethod]
        public async Task GetUdpAssociateHandlerAsync_NoManagersForFamily_ThrowsNetworkUnreachable()
        {
            using var manager = new LoadBalancingProxyServerConnectionManager(
                Array.Empty<IProxyServerConnectionManager>(),
                Array.Empty<IProxyServerConnectionManager>(),
                new[] { DummyConnectivityEndPoint });

            var localEp = new IPEndPoint(IPAddress.Loopback, 0);

            SocketException ex = await Assert.ThrowsExactlyAsync<SocketException>(
                () => manager.GetUdpAssociateHandlerAsync(localEp),
                "GetUdpAssociateHandlerAsync must fail when no managers exist for the endpoint family.");

            Assert.AreEqual(
                SocketError.NetworkUnreachable,
                ex.SocketErrorCode,
                "UDP associate lookup must surface NetworkUnreachable when no managers exist.");
        }

        #endregion

        #region fakes

        private sealed class FakeConnectionManager : IProxyServerConnectionManager, IDisposable
        {
            public AddressFamily Family { get; }

            public int ConnectCallCount { get; private set; }

            public EndPoint LastRemoteEndPoint { get; private set; }

            public int BindCallCount { get; private set; }

            public int UdpCallCount { get; private set; }

            public bool ShouldThrow { get; }

            public SocketError ThrowError { get; set; } = SocketError.NetworkUnreachable;

            public IProxyServerBindHandler BindHandler { get; set; }

            public IProxyServerUdpAssociateHandler UdpHandler { get; set; }

            public FakeConnectionManager(AddressFamily family)
            {
                Family = family;
                BindHandler = new FakeBindHandler(family);
                UdpHandler = new FakeUdpHandler(family);
            }

            public Task<Socket> ConnectAsync(EndPoint remoteEP, CancellationToken cancellationToken = default)
            {
                ConnectCallCount++;
                LastRemoteEndPoint = remoteEP;

                if (ShouldThrow)
                    throw new SocketException((int)ThrowError);

                var socket = new Socket(Family, SocketType.Stream, ProtocolType.Tcp);
                return Task.FromResult(socket);
            }

            public Task<IProxyServerBindHandler> GetBindHandlerAsync(AddressFamily family)
            {
                BindCallCount++;

                if (ShouldThrow)
                    throw new SocketException((int)ThrowError);

                return Task.FromResult(BindHandler);
            }

            public Task<IProxyServerUdpAssociateHandler> GetUdpAssociateHandlerAsync(EndPoint localEP)
            {
                UdpCallCount++;

                if (ShouldThrow)
                    throw new SocketException((int)ThrowError);

                return Task.FromResult(UdpHandler);
            }

            public void Dispose()
            {
                // Nothing to dispose in this fake; sockets returned to tests are disposed there.
            }
        }

        private sealed class FakeBindHandler : IProxyServerBindHandler
        {
            public SocksProxyReplyCode ReplyCode { get; }

            public EndPoint ProxyRemoteEndPoint { get; }

            public EndPoint ProxyLocalEndPoint { get; }

            public FakeBindHandler(AddressFamily family)
            {
                var address = family == AddressFamily.InterNetwork
                    ? IPAddress.Loopback
                    : IPAddress.IPv6Loopback;

                ProxyLocalEndPoint = new IPEndPoint(address, 10000);
                ProxyRemoteEndPoint = new IPEndPoint(address, 20000);
                ReplyCode = SocksProxyReplyCode.Succeeded;
            }

            public Task<Socket> AcceptAsync(CancellationToken cancellationToken = default)
            {
                var socket = new Socket(
                    ((IPEndPoint)ProxyLocalEndPoint).AddressFamily,
                    SocketType.Stream,
                    ProtocolType.Tcp);

                return Task.FromResult(socket);
            }

            public void Dispose()
            {
                // No resources allocated by this fake.
            }
        }

        private sealed class FakeUdpHandler : IProxyServerUdpAssociateHandler
        {
            private readonly AddressFamily _family;

            public FakeUdpHandler(AddressFamily family)
            {
                _family = family;
            }

            public Task<int> SendToAsync(ArraySegment<byte> buffer, EndPoint remoteEP, CancellationToken cancellationToken = default)
            {
                // Echo back the buffer length to simulate a successful send.
                return Task.FromResult(buffer.Count);
            }

            public Task<SocketReceiveFromResult> ReceiveFromAsync(ArraySegment<byte> buffer, CancellationToken cancellationToken = default)
            {
                var result = new SocketReceiveFromResult
                {
                    ReceivedBytes = 0,
                    RemoteEndPoint = new IPEndPoint(
                        _family == AddressFamily.InterNetwork ? IPAddress.Loopback : IPAddress.IPv6Loopback,
                        53)
                };

                return Task.FromResult(result);
            }

            public void Dispose()
            {
                // Nothing to dispose in this fake.
            }
        }

        #endregion
    }
}
