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
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public sealed class UdpTunnelProxyTests
    {
        [TestMethod]
        public void Constructor_MustExposeTunnelEndPoint()
        {
            using Socket remoteSocket =
                new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            remoteSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

            using UdpTunnelProxy tunnel =
                new UdpTunnelProxy(remoteSocket, remoteSocket.LocalEndPoint);

            IPEndPoint tunnelEP = tunnel.TunnelEndPoint;

            Assert.IsNotNull(
                tunnelEP,
                "UdpTunnelProxy must expose a tunnel endpoint immediately after construction.");

            Assert.IsGreaterThan(
0,
                tunnelEP.Port, "UdpTunnelProxy must bind an ephemeral UDP port.");
        }

        [TestMethod]
        public void Dispose_MustStopTunnelAndMarkBroken()
        {
            using Socket remoteSocket =
                new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            remoteSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

            UdpTunnelProxy tunnel =
                new UdpTunnelProxy(remoteSocket, remoteSocket.LocalEndPoint);

            tunnel.Dispose();
            tunnel.Dispose(); // idempotent

            Assert.IsTrue(
                tunnel.IsBroken,
                "Dispose must mark UdpTunnelProxy as broken and prevent further relay activity.");
        }

        [TestMethod]
        public async Task Tunnel_MustForwardDatagram_FromTunnelClient_ToRemoteSocket()
        {
            using Socket remoteSocket =
                new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            remoteSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            IPEndPoint remoteEP = (IPEndPoint)remoteSocket.LocalEndPoint!;

            using UdpTunnelProxy tunnel =
                new UdpTunnelProxy(remoteSocket, remoteEP);

            using Socket tunnelClient =
                new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            byte[] payload = Encoding.ASCII.GetBytes("udp-ping");

            byte[] buffer = new byte[32];
            EndPoint anyEP = new IPEndPoint(IPAddress.Any, 0);

            Task<SocketReceiveFromResult> receiveTask =
                remoteSocket.ReceiveFromAsync(buffer, SocketFlags.None, anyEP);

            await tunnelClient.SendToAsync(
                payload,
                SocketFlags.None,
                tunnel.TunnelEndPoint);

            SocketReceiveFromResult result = await receiveTask;

            CollectionAssert.AreEqual(
                payload,
                buffer.AsSpan(0, result.ReceivedBytes).ToArray(),
                "Datagram sent to TunnelEndPoint must reach the remote socket unmodified.");
        }
    }
}