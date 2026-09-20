using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public sealed class TunnelProxyTests
    {
        [TestMethod]
        public async Task Constructor_MustExposeConnectableTunnelEndPoint()
        {
            using TcpListener remoteListener = new TcpListener(IPAddress.Loopback, 0);
            remoteListener.Start();

            using Socket remoteClient = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            Task<Socket> acceptTask = remoteListener.AcceptSocketAsync();
            await remoteClient.ConnectAsync(remoteListener.LocalEndpoint);
            using Socket remoteServer = await acceptTask;

            using TunnelProxy tunnel = new TunnelProxy(
                remoteServer,
                remoteListener.LocalEndpoint,
                enableSsl: false,
                ignoreCertificateErrors: false);

            using Socket tunnelClient = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await tunnelClient.ConnectAsync(tunnel.TunnelEndPoint);

            Assert.IsTrue(
                tunnelClient.Connected,
                "TunnelProxy must expose a connectable tunnel endpoint immediately after construction.");
        }

        [TestMethod]
        public async Task Tunnel_MustForwardData_FromTunnelClient_ToRemoteSocket()
        {
            using TcpListener remoteListener = new TcpListener(IPAddress.Loopback, 0);
            remoteListener.Start();

            using Socket remoteClient = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            Task<Socket> acceptTask = remoteListener.AcceptSocketAsync();
            await remoteClient.ConnectAsync(remoteListener.LocalEndpoint);
            using Socket remoteServer = await acceptTask;

            using TunnelProxy tunnel = new TunnelProxy(
                remoteServer,
                remoteListener.LocalEndpoint,
                enableSsl: false,
                ignoreCertificateErrors: false);

            using Socket tunnelClient = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await tunnelClient.ConnectAsync(tunnel.TunnelEndPoint);

            byte[] payload = Encoding.ASCII.GetBytes("ping");
            await tunnelClient.SendAsync(payload, SocketFlags.None);

            byte[] buffer = new byte[4];
            int received = await remoteClient.ReceiveAsync(buffer, SocketFlags.None);

            CollectionAssert.AreEqual(
                payload,
                buffer[..received],
                "Bytes written to the tunnel endpoint must reach the remote socket without mutation.");
        }

        [TestMethod]
        public async Task Tunnel_MustForwardData_FromRemoteSocket_ToTunnelClient()
        {
            using TcpListener remoteListener = new TcpListener(IPAddress.Loopback, 0);
            remoteListener.Start();

            using Socket remoteClient = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            Task<Socket> acceptTask = remoteListener.AcceptSocketAsync();
            await remoteClient.ConnectAsync(remoteListener.LocalEndpoint);
            using Socket remoteServer = await acceptTask;

            using TunnelProxy tunnel = new TunnelProxy(
                remoteServer,
                remoteListener.LocalEndpoint,
                enableSsl: false,
                ignoreCertificateErrors: false);

            using Socket tunnelClient = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await tunnelClient.ConnectAsync(tunnel.TunnelEndPoint);

            byte[] payload = Encoding.ASCII.GetBytes("pong");
            await remoteClient.SendAsync(payload, SocketFlags.None);

            byte[] buffer = new byte[4];
            int received = await tunnelClient.ReceiveAsync(buffer, SocketFlags.None);

            CollectionAssert.AreEqual(
                payload,
                buffer[..received],
                "Bytes written by the remote socket must be forwarded to the tunnel client without mutation.");
        }

        [TestMethod]
        public async Task Dispose_MustBreakTunnelAndRejectNewConnections()
        {
            using TcpListener remoteListener = new TcpListener(IPAddress.Loopback, 0);
            remoteListener.Start();

            using Socket remoteClient = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            Task<Socket> acceptTask = remoteListener.AcceptSocketAsync();
            await remoteClient.ConnectAsync(remoteListener.LocalEndpoint);
            using Socket remoteServer = await acceptTask;

            TunnelProxy tunnel = new TunnelProxy(
                remoteServer,
                remoteListener.LocalEndpoint,
                enableSsl: false,
                ignoreCertificateErrors: false);

            IPEndPoint tunnelEP = tunnel.TunnelEndPoint;

            tunnel.Dispose();
            tunnel.Dispose(); // idempotency

            Assert.IsTrue(
                tunnel.IsBroken,
                "Dispose must mark TunnelProxy as broken.");

            using Socket tunnelClient = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            await Assert.ThrowsExactlyAsync<SocketException>(
                () => tunnelClient.ConnectAsync(tunnelEP),
                "Disposed TunnelProxy must not accept new tunnel connections.");
        }
    }
}
