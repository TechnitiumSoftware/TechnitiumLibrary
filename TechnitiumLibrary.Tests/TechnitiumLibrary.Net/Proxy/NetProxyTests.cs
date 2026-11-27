using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public class NetProxyTests
    {
        public TestContext TestContext { get; set; }

        #region helpers

        private static TcpListener StartListener(IPAddress address, out IPEndPoint localEndPoint)
        {
            var listener = new TcpListener(address, 0);
            listener.Start();

            Assert.IsNotNull(listener.LocalEndpoint, "Listener.LocalEndpoint must be initialized after Start().");
            Assert.IsInstanceOfType(
                listener.LocalEndpoint,
                typeof(IPEndPoint),
                "Listener.LocalEndpoint must be an IPEndPoint instance.");

            localEndPoint = (IPEndPoint)listener.LocalEndpoint!;
            return listener;
        }

        /// <summary>
        /// Concrete NetProxy implementation that simply returns the viaSocket,
        /// while recording the parameters passed to the protected ConnectAsync.
        /// </summary>
        private sealed class TestNetProxy : NetProxy
        {
            public int ProtectedConnectCallCount { get; private set; }

            public EndPoint? LastRemoteEndPoint { get; private set; }

            public Socket? LastViaSocket { get; private set; }

            public TestNetProxy(EndPoint proxyEp)
                : base(NetProxyType.Http, proxyEp)
            {
            }

            protected override Task<Socket> ConnectAsync(EndPoint remoteEP, Socket viaSocket, CancellationToken cancellationToken)
            {
                ProtectedConnectCallCount++;
                LastRemoteEndPoint = remoteEP;
                LastViaSocket = viaSocket;
                return Task.FromResult(viaSocket);
            }
        }

        /// <summary>
        /// Concrete NetProxy used as viaProxy in chaining tests.
        /// Records its protected ConnectAsync calls.
        /// </summary>
        private sealed class ChainedNetProxy : NetProxy
        {
            public int ProtectedConnectCallCount { get; private set; }

            public EndPoint? LastRemoteEndPoint { get; private set; }

            public EndPoint? LastProxyEndPointSeen { get; private set; }

            public ChainedNetProxy(EndPoint proxyEp)
                : base(NetProxyType.Http, proxyEp)
            {
            }

            protected override Task<Socket> ConnectAsync(EndPoint remoteEP, Socket viaSocket, CancellationToken cancellationToken)
            {
                ProtectedConnectCallCount++;
                LastRemoteEndPoint = remoteEP;
                LastProxyEndPointSeen = ProxyEndPoint;
                return Task.FromResult(viaSocket);
            }
        }

        #endregion

        #region tests

        [TestMethod]
        public async Task ConnectAsync_BypassedEndpoint_UsesDirectTcpAndSkipsProtectedConnect()
        {
            // Arrange: loopback is in the default bypass list.
            TcpListener listener = StartListener(IPAddress.Loopback, out IPEndPoint remoteEp);

            // proxyEP value is irrelevant for bypassed endpoints; it will not be used.
            var proxyEp = new IPEndPoint(IPAddress.Loopback, 65000);
            var proxy = new TestNetProxy(proxyEp);

            // Act
            using Socket socket = await proxy.ConnectAsync(remoteEp, TestContext.CancellationToken);

            // Accept the incoming connection to complete the TCP handshake.
            using Socket serverSide = await listener.AcceptSocketAsync(TestContext.CancellationToken);

            // Assert
            Assert.IsTrue(socket.Connected, "Bypassed endpoint must result in a direct TCP connection to the remote endpoint.");
            Assert.AreEqual(
                0,
                proxy.ProtectedConnectCallCount,
                "Protected ConnectAsync(remote, viaSocket) must not be called for bypassed endpoints.");

            listener.Stop();
        }

        [TestMethod]
        public async Task ConnectAsync_NonBypassedEndpoint_ConnectsToProxyEndpointAndInvokesProtectedConnect()
        {
            // Arrange: choose an address that is NOT in the default bypass list (203.0.113.77).
            var remote = new IPEndPoint(IPAddress.Parse("203.0.113.77"), 9000);

            // NetProxy must first connect to _proxyEP.
            TcpListener proxyListener = StartListener(IPAddress.Loopback, out IPEndPoint proxyEp);

            var proxy = new TestNetProxy(proxyEp);

            // Act
            using Socket socket = await proxy.ConnectAsync(remote, TestContext.CancellationToken);

            // Accept the TCP connection that GetTcpConnectionAsync opened to proxyEp.
            using Socket serverSide = await proxyListener.AcceptSocketAsync(TestContext.CancellationToken);

            // Assert
            Assert.AreEqual(
                1,
                proxy.ProtectedConnectCallCount,
                "Protected ConnectAsync must be called exactly once for non-bypassed endpoints.");

            Assert.AreEqual(
                remote,
                proxy.LastRemoteEndPoint,
                "Protected ConnectAsync must see the original remote endpoint, not the proxy endpoint.");

            Assert.IsNotNull(
                proxy.LastViaSocket,
                "Protected ConnectAsync must receive a viaSocket representing a TCP connection to the proxy endpoint.");

            Assert.AreSame(
                socket,
                proxy.LastViaSocket,
                "Public ConnectAsync must return exactly the viaSocket passed into the protected overload.");

            Assert.IsTrue(
                socket.Connected,
                "Socket returned by ConnectAsync must represent a live TCP connection to the proxy endpoint.");

            proxyListener.Stop();
        }

        [TestMethod]
        public async Task ConnectAsync_ChainOfProxies_UsesViaProxyThenMainProxy()
        {
            // Arrange:
            // viaProxy has its own proxy endpoint where it will open a TCP connection
            // when connecting to mainProxy.ProxyEndPoint.
            TcpListener viaProxyListener = StartListener(IPAddress.Loopback, out IPEndPoint viaProxyEp);
            var viaProxy = new ChainedNetProxy(viaProxyEp)
            {
                // Ensure that mainProxy.ProxyEndPoint is NOT bypassed for viaProxy.
                BypassList = Array.Empty<NetProxyBypassItem>()
            };

            // Main proxy has its own upstream endpoint; this is the remoteEP passed into viaProxy.
            var mainProxyEp = new IPEndPoint(IPAddress.Loopback, 60000);
            var mainProxy = new TestNetProxy(mainProxyEp)
            {
                ViaProxy = viaProxy
            };

            // Target endpoint is non-bypassed for mainProxy.
            var target = new IPEndPoint(IPAddress.Parse("203.0.113.44"), 443);

            // Act
            using Socket finalSocket = await mainProxy.ConnectAsync(target, TestContext.CancellationToken);

            // viaProxy must receive a ConnectAsync call with remoteEP = mainProxy.ProxyEndPoint
            Assert.AreEqual(
                1,
                viaProxy.ProtectedConnectCallCount,
                "Via proxy must have its protected ConnectAsync invoked exactly once.");

            Assert.AreEqual(
                mainProxyEp,
                viaProxy.LastRemoteEndPoint,
                "Via proxy must be asked to connect to the main proxy endpoint.");

            // Accept the TCP connection that viaProxy's GetTcpConnectionAsync opened
            // to its own proxy endpoint.
            using Socket viaProxyServerSide = await viaProxyListener.AcceptSocketAsync(TestContext.CancellationToken);

            // Then main proxy must be invoked with the final target.
            Assert.AreEqual(
                1,
                mainProxy.ProtectedConnectCallCount,
                "Main proxy must have its protected ConnectAsync invoked exactly once.");

            Assert.AreEqual(
                target,
                mainProxy.LastRemoteEndPoint,
                "Main proxy protected ConnectAsync must see the original target endpoint.");

            Assert.IsTrue(
                finalSocket.Connected,
                "Final socket must represent the TCP connection established by viaProxy to its own proxy endpoint.");

            viaProxyListener.Stop();
        }

        [TestMethod]
        public void BypassList_CanBeReplacedAndAffectsIsBypassed()
        {
            var proxyEp = new IPEndPoint(IPAddress.Loopback, 8080);
            var proxy = new TestNetProxy(proxyEp);

            // Replace default bypass list with a custom one.
            proxy.BypassList = new[]
            {
                new NetProxyBypassItem("192.168.10.0/24")
            };

            var bypassed = new IPEndPoint(IPAddress.Parse("192.168.10.5"), 80);
            var notBypassed = new IPEndPoint(IPAddress.Loopback, 80); // not in our custom list

            Assert.IsTrue(
                proxy.IsBypassed(bypassed),
                "Endpoint inside configured CIDR must be treated as bypassed.");

            Assert.IsFalse(
                proxy.IsBypassed(notBypassed),
                "Endpoint outside custom bypass list must not be bypassed.");
        }

        #endregion
    }
}
