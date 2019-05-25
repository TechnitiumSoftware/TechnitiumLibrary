/*
Technitium Library
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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

using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.ClientConnection
{
    public class UdpClientConnection : DnsClientConnection
    {
        #region constructor

        public UdpClientConnection(NameServerAddress server, NetProxy proxy)
            : base(DnsTransportProtocol.Udp, server, proxy)
        {
            if (proxy != null)
            {
                if (proxy.Type == NetProxyType.Http)
                    throw new NotSupportedException("DnsClient cannot use HTTP proxy with UDP protocol.");
            }

            _timeout = 2000;
        }

        #endregion

        #region public

        public override DnsDatagram Query(DnsDatagram request)
        {
            //serialize request
            byte[] buffer = new byte[512];
            int bufferSize;

            using (MemoryStream mS = new MemoryStream(buffer))
            {
                try
                {
                    request.WriteTo(mS);
                }
                catch (NotSupportedException)
                {
                    throw new DnsClientException("DnsClient cannot send request of more than 512 bytes with UDP protocol.");
                }

                bufferSize = (int)mS.Position;
            }

            DateTime sentAt = DateTime.UtcNow;

            if (_proxy == null)
            {
                if (_server.IPEndPoint == null)
                    _server.RecursiveResolveIPAddress();

                using (Socket socket = new Socket(_server.IPEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
                {
                    socket.ReceiveTimeout = _timeout;

                    //send request
                    socket.SendTo(buffer, 0, bufferSize, SocketFlags.None, _server.IPEndPoint);

                    //receive request
                    EndPoint remoteEP;

                    if (_server.IPEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
                        remoteEP = new IPEndPoint(IPAddress.IPv6Any, 0);
                    else
                        remoteEP = new IPEndPoint(IPAddress.Any, 0);

                    do
                    {
                        bufferSize = socket.ReceiveFrom(buffer, ref remoteEP);
                    }
                    while (!_server.IPEndPoint.Equals(remoteEP));
                }
            }
            else
            {
                bufferSize = _proxy.UdpReceiveFrom(_server.EndPoint, buffer, buffer, _timeout);
            }

            //parse response
            using (MemoryStream mS = new MemoryStream(buffer, 0, bufferSize, false))
            {
                DnsDatagram response = new DnsDatagram(mS);

                response.SetMetadata(new DnsDatagramMetadata(_server, _protocol, bufferSize, (DateTime.UtcNow - sentAt).TotalMilliseconds));

                if (response.Header.Identifier == request.Header.Identifier)
                    return response;
            }

            return null;
        }

        #endregion
    }
}
