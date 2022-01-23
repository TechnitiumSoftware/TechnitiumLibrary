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

using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.ClientConnection
{
    public class TlsClientConnection : TcpClientConnection
    {
        #region constructor

        public TlsClientConnection(NameServerAddress server, NetProxy proxy)
            : base(DnsTransportProtocol.Tls, server, proxy)
        { }

        #endregion

        #region protected

        protected override async Task<Stream> GetNetworkStreamAsync(Socket socket, CancellationToken cancellationToken)
        {
            SslStream tlsStream = new SslStream(new NetworkStream(socket, true));
            await tlsStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions() { TargetHost = _server.Host }, cancellationToken);

            return tlsStream;
        }

        #endregion
    }
}
