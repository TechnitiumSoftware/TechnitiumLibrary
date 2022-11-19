/*
Technitium Library
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.ClientConnection
{
    public class UdpClientConnection : DnsClientConnection
    {
        #region constructor

        public UdpClientConnection(NameServerAddress server, NetProxy proxy)
            : base(DnsTransportProtocol.Udp, server, proxy)
        { }

        #endregion

        #region public

        public override async Task<DnsDatagram> QueryAsync(DnsDatagram request, int timeout, int retries, CancellationToken cancellationToken)
        {
            //serialize request
            byte[] buffer;

            if (request.EDNS is null)
                buffer = new byte[512];
            else if (request.EDNS.UdpPayloadSize > 4096)
                buffer = new byte[4096];
            else
                buffer = new byte[request.EDNS.UdpPayloadSize];

            MemoryStream bufferStream = new MemoryStream(buffer);

            try
            {
                request.WriteTo(bufferStream);
            }
            catch (NotSupportedException)
            {
                throw new DnsClientException("DnsClient cannot send the request: request exceeds the UDP payload size limit of " + buffer.Length + " bytes.");
            }

            int bufferSize = (int)bufferStream.Position;
            Stopwatch stopwatch = new Stopwatch();

            if (_proxy == null)
            {
                if (_server.IsIPEndPointStale)
                    await _server.RecursiveResolveIPAddressAsync(null, null, false, DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE, false, 2, 2000, cancellationToken);

                using (Socket socket = new Socket(_server.IPEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
                {
                    stopwatch.Start();

                    bufferSize = await socket.UdpQueryAsync(new ArraySegment<byte>(buffer, 0, bufferSize), buffer, _server.IPEndPoint, timeout, retries, false, cancellationToken);

                    stopwatch.Stop();
                }
            }
            else
            {
                stopwatch.Start();

                bufferSize = await _proxy.UdpQueryAsync(new ArraySegment<byte>(buffer, 0, bufferSize), buffer, _server.EndPoint, timeout, retries, false, cancellationToken);

                stopwatch.Stop();
            }

            //parse response
            bufferStream.Position = 0;
            bufferStream.SetLength(bufferSize);

            DnsDatagram response = DnsDatagram.ReadFrom(bufferStream);

            response.SetMetadata(_server, _protocol, stopwatch.Elapsed.TotalMilliseconds);

            ValidateResponse(request, response);

            return response;
        }

        #endregion
    }
}
