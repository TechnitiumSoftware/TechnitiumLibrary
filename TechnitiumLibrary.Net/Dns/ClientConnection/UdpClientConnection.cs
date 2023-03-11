/*
Technitium Library
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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
using System.Runtime.ExceptionServices;
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
            byte[] sendBuffer;
            int sendBufferSize;

            if (request.EDNS is null)
                sendBuffer = new byte[512];
            else if (request.EDNS.UdpPayloadSize > DnsDatagram.EDNS_MAX_UDP_PAYLOAD_SIZE)
                sendBuffer = new byte[DnsDatagram.EDNS_MAX_UDP_PAYLOAD_SIZE];
            else
                sendBuffer = new byte[request.EDNS.UdpPayloadSize];

            try
            {
                using (MemoryStream mS = new MemoryStream(sendBuffer))
                {
                    request.WriteTo(mS);
                    sendBufferSize = (int)mS.Position;
                }
            }
            catch (NotSupportedException)
            {
                throw new DnsClientException("DnsClient cannot send the request: request exceeds the UDP payload size limit of " + sendBuffer.Length + " bytes.");
            }

            byte[] receiveBuffer = new byte[sendBuffer.Length];
            Stopwatch stopwatch = new Stopwatch();
            DnsDatagram lastResponse = null;
            Exception lastException = null;

            bool IsResponseValid(int receivedBytes)
            {
                try
                {
                    //parse response
                    using (MemoryStream mS = new MemoryStream(receiveBuffer, 0, receivedBytes))
                    {
                        DnsDatagram response = DnsDatagram.ReadFrom(mS);
                        response.SetMetadata(_server, _protocol, stopwatch.Elapsed.TotalMilliseconds);

                        ValidateResponse(request, response);

                        lastResponse = response;
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    lastException = ex;
                    return false;
                }
            }

            if (_proxy is null)
            {
                if (_server.IsIPEndPointStale)
                    await _server.RecursiveResolveIPAddressAsync(null, null, false, DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE, false, 2, 2000, cancellationToken);

                using (Socket socket = new Socket(_server.IPEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
                {
                    stopwatch.Start();

                    _ = await socket.UdpQueryAsync(new ArraySegment<byte>(sendBuffer, 0, sendBufferSize), receiveBuffer, _server.IPEndPoint, timeout, retries, false, IsResponseValid, cancellationToken);

                    stopwatch.Stop();
                }
            }
            else
            {
                stopwatch.Start();

                _ = await _proxy.UdpQueryAsync(new ArraySegment<byte>(sendBuffer, 0, sendBufferSize), receiveBuffer, _server.EndPoint, timeout, retries, false, IsResponseValid, cancellationToken);

                stopwatch.Stop();
            }

            if (lastResponse is not null)
                return lastResponse;

            if (lastException is not null)
                ExceptionDispatchInfo.Throw(lastException);

            throw new InvalidOperationException();
        }

        #endregion
    }
}
