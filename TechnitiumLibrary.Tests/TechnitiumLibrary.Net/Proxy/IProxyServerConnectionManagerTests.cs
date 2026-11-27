using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public sealed class IProxyServerConnectionManagerTests
    {
        [TestMethod]
        public async Task ConnectAsync_MustHonorCancellation()
        {
            using CancellationTokenSource cts = new CancellationTokenSource();
            cts.Cancel();

            IProxyServerConnectionManager manager = new ContractTestConnectionManager();

            await Assert.ThrowsExactlyAsync<OperationCanceledException>(
                () => manager.ConnectAsync(
                    new IPEndPoint(IPAddress.Loopback, 1),
                    cts.Token),
                "ConnectAsync must honor pre-cancelled tokens deterministically.");
        }

        [TestMethod]
        public async Task ConnectAsync_MustNotLeakSocket_OnCancellation()
        {
            using CancellationTokenSource cts =
                new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

            IProxyServerConnectionManager manager = new ContractTestConnectionManager();

            await Assert.ThrowsExactlyAsync<OperationCanceledException>(
                () => manager.ConnectAsync(
                    new IPEndPoint(IPAddress.Parse("192.0.2.1"), 65000),
                    cts.Token),
                "ConnectAsync must release resources cleanly when cancelled during connection attempt.");
        }

        [TestMethod]
        public async Task ConnectAsync_MustRejectUnsupportedEndpointTypes()
        {
            IProxyServerConnectionManager manager = new ContractTestConnectionManager();

            await Assert.ThrowsExactlyAsync<NotSupportedException>(
                () => manager.ConnectAsync(
                    new DnsEndPoint("example.com", 80),
                    CancellationToken.None),
                "Unsupported EndPoint types must be rejected deterministically.");
        }

        [TestMethod]
        public async Task ConnectAsync_MustReturnConnectedSocket_OnSuccess()
        {
            using TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();

            IPEndPoint target = (IPEndPoint)listener.LocalEndpoint;

            IProxyServerConnectionManager manager = new ContractTestConnectionManager();

            using Socket client = await manager.ConnectAsync(target);

            Assert.IsTrue(client.Connected,
                "ConnectAsync must return a socket that is already connected.");

            using Socket server = await listener.AcceptSocketAsync();
            Assert.IsTrue(server.Connected,
                "Returned socket must result in an observable server-side connection.");
        }

        private sealed class ContractTestConnectionManager : IProxyServerConnectionManager
        {
            public async Task<Socket> ConnectAsync(EndPoint remoteEP, CancellationToken cancellationToken = default)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (remoteEP is not IPEndPoint ip)
                    throw new NotSupportedException("Only IPEndPoint supported by contract test.");

                Socket socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                try
                {
                    await socket.ConnectAsync(ip, cancellationToken);
                    socket.NoDelay = true;
                    return socket;
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            }

            public Task<IProxyServerBindHandler> GetBindHandlerAsync(AddressFamily family)
                => throw new NotSupportedException();

            public Task<IProxyServerUdpAssociateHandler> GetUdpAssociateHandlerAsync(EndPoint localEP)
                => throw new NotSupportedException();
        }
    }
}