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
using System.Text;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Proxy
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
            Task<Socket> acceptTask = remoteListener.AcceptSocketAsync(TestContext.CancellationToken).AsTask();
            await remoteClient.ConnectAsync(remoteListener.LocalEndpoint, TestContext.CancellationToken);
            using Socket remoteServer = await acceptTask;

            using TunnelProxy tunnel = new TunnelProxy(
                remoteServer,
                remoteListener.LocalEndpoint,
                enableSsl: false,
                ignoreCertificateErrors: false);

            using Socket tunnelClient = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await tunnelClient.ConnectAsync(tunnel.TunnelEndPoint, TestContext.CancellationToken);

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
            Task<Socket> acceptTask = remoteListener.AcceptSocketAsync(TestContext.CancellationToken).AsTask();
            await remoteClient.ConnectAsync(remoteListener.LocalEndpoint, TestContext.CancellationToken);
            using Socket remoteServer = await acceptTask;

            using TunnelProxy tunnel = new TunnelProxy(
                remoteServer,
                remoteListener.LocalEndpoint,
                enableSsl: false,
                ignoreCertificateErrors: false);

            using Socket tunnelClient = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await tunnelClient.ConnectAsync(tunnel.TunnelEndPoint, TestContext.CancellationToken);

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
            Task<Socket> acceptTask = remoteListener.AcceptSocketAsync(TestContext.CancellationToken).AsTask();
            await remoteClient.ConnectAsync(remoteListener.LocalEndpoint, TestContext.CancellationToken);
            using Socket remoteServer = await acceptTask;

            using TunnelProxy tunnel = new TunnelProxy(
                remoteServer,
                remoteListener.LocalEndpoint,
                enableSsl: false,
                ignoreCertificateErrors: false);

            using Socket tunnelClient = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await tunnelClient.ConnectAsync(tunnel.TunnelEndPoint, TestContext.CancellationToken);

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
            Task<Socket> acceptTask = remoteListener.AcceptSocketAsync(TestContext.CancellationToken).AsTask();
            await remoteClient.ConnectAsync(remoteListener.LocalEndpoint, TestContext.CancellationToken);
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
                () => tunnelClient.ConnectAsync(tunnelEP, TestContext.CancellationToken).AsTask(),
                "Disposed TunnelProxy must not accept new tunnel connections.");
        }

        public TestContext TestContext { get; set; }
    }
}