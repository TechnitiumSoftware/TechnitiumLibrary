/*
Technitium Library
Copyright (C) 2020  Shreyas Zare (shreyas@technitium.com)

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
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.ClientConnection
{
    public class UdpClientConnection : DnsClientConnection
    {
        #region variables

        readonly Socket _socket;

        #endregion

        #region constructor

        public UdpClientConnection(NameServerAddress server, NetProxy proxy)
            : base(DnsTransportProtocol.Udp, server, proxy)
        {
            if ((proxy != null) && !proxy.IsUdpAvailable())
                throw new NotSupportedException("Current configured proxy does not support UDP protocol.");

            if (_proxy == null)
                _socket = new Socket(_server.IPEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        }

        #endregion

        #region IDisposable

        bool _disposed;

        protected override void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_socket != null)
                    _socket.Dispose();
            }

            _disposed = true;
        }

        #endregion

        #region public

        public override async Task<DnsDatagram> QueryAsync(DnsDatagram request, int timeout)
        {
            //serialize request
            byte[] buffer = new byte[512];
            int bufferSize;

            using (MemoryStream mS = new MemoryStream(buffer))
            {
                try
                {
                    request.WriteToUdp(mS);
                }
                catch (NotSupportedException)
                {
                    throw new DnsClientException("DnsClient cannot send request of more than 512 bytes with UDP protocol.");
                }

                bufferSize = (int)mS.Position;
            }

            Stopwatch stopwatch = new Stopwatch();

            if (_proxy == null)
            {
                if (_server.IPEndPoint == null)
                    _server.RecursiveResolveIPAddress();

                _socket.ReceiveTimeout = timeout;

                stopwatch.Start();

                //send request
                await _socket.SendToAsync(buffer, 0, bufferSize, SocketFlags.None, _server.IPEndPoint);

                //receive request
                while (true)
                {
                    ReceiveFromResult result = await _socket.ReceiveFromAsync(buffer, 0, buffer.Length, SocketFlags.None);

                    if (_server.IPEndPoint.Equals(result.RemoteEndPoint))
                    {
                        bufferSize = result.BytesReceived;
                        break;
                    }
                }

                stopwatch.Stop();
            }
            else
            {
                stopwatch.Start();

                bufferSize = _proxy.UdpReceiveFrom(_server.EndPoint, buffer, 0, bufferSize, buffer, 0, timeout);

                stopwatch.Stop();
            }

            //parse response
            using (MemoryStream mS = new MemoryStream(buffer, 0, bufferSize, false))
            {
                DnsDatagram response = new DnsDatagram(mS, false);

                response.SetMetadata(new DnsDatagramMetadata(_server, _protocol, bufferSize, stopwatch.Elapsed.TotalMilliseconds));

                if (response.Identifier == request.Identifier)
                    return response;
            }

            return null;
        }

        #endregion
    }
}
