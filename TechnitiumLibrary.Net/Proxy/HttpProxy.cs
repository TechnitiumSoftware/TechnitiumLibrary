/*
Technitium Library
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.Proxy
{
    public class HttpProxy : NetProxy
    {
        #region variables

        private static readonly char[] spaceSeparator = new char[] { ' ' };

        #endregion

        #region constructors

        public HttpProxy(EndPoint proxyEP, NetworkCredential credential = null)
            : base(NetProxyType.Http, proxyEP, credential)
        { }

        #endregion

        #region public

        public override Uri GetProxy(Uri destination)
        {
            if (_viaProxy != null)
                return base.GetProxy(destination);

            if (IsBypassed(destination))
                return destination;

            return new Uri("http://" + _proxyEP.ToString());
        }

        #endregion

        #region protected

        protected override async Task<Socket> ConnectAsync(EndPoint remoteEP, Socket viaSocket, CancellationToken cancellationToken)
        {
            try
            {
                string httpConnectRequest = "CONNECT " + remoteEP.ToString() + " HTTP/1.0\r\n";

                if (_credential != null)
                    httpConnectRequest += "Proxy-Authorization: Basic " + Convert.ToBase64String(Encoding.ASCII.GetBytes(_credential.UserName + ":" + _credential.Password)) + "\r\n";

                httpConnectRequest += "\r\n";

                await viaSocket.SendAsync(Encoding.ASCII.GetBytes(httpConnectRequest), SocketFlags.None, cancellationToken);

                byte[] buffer = new byte[128];
                int bytesRecv = await viaSocket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken);

                if (bytesRecv < 1)
                    throw new HttpProxyException("No response was received from http proxy server.");

                string httpResponse = Encoding.ASCII.GetString(buffer, 0, bytesRecv);
                string[] httpResponseParts = httpResponse.Split('\r')[0].Split(spaceSeparator, 3);

                if (httpResponseParts.Length != 3)
                    throw new HttpProxyException("Invalid response received from remote server: " + httpResponse);

                switch (httpResponseParts[1])
                {
                    case "200":
                        return viaSocket;

                    case "407":
                        throw new HttpProxyAuthenticationFailedException("The remote server returned an error: (" + httpResponseParts[1] + ") Proxy Authorization Required");

                    default:
                        throw new HttpProxyException("The remote server returned an error: (" + httpResponseParts[1] + ") " + httpResponseParts[2]);
                }
            }
            catch
            {
                viaSocket.Dispose();
                throw;
            }
        }

        #endregion
    }
}
