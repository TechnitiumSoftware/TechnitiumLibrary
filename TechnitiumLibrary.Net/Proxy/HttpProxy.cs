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
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace TechnitiumLibrary.Net.Proxy
{
    public class HttpProxy : NetProxy, IWebProxy
    {
        #region constructors

        public HttpProxy(EndPoint proxyEP, NetworkCredential credential)
            : base(NetProxyType.Http, proxyEP, credential)
        { }

        #endregion

        #region public

        public Uri GetProxy(Uri destination)
        {
            if (_viaProxy != null)
                throw new NotSupportedException("Http proxying with proxy chaining is not supported.");

            if (IsBypassed(destination))
                return destination;

            return new Uri("http://" + _proxyEP.ToString());
        }

        public bool IsBypassed(Uri host)
        {
            return IsBypassed(EndPointExtension.GetEndPoint(host.Host, host.Port));
        }

        public override bool IsProxyAvailable()
        {
            try
            {
                using (Socket socket = GetTcpConnection(_proxyEP, 5000))
                { }

                return true;
            }
            catch
            {
                return false;
            }
        }

        public override void CheckProxyAccess()
        {
            using (Socket socket = GetTcpConnection(_proxyEP, 5000))
            { }
        }

        public override bool IsUdpAvailable()
        {
            return false;
        }

        public override int UdpReceiveFrom(EndPoint remoteEP, byte[] request, int requestOffset, int requestSize, byte[] response, int responseOffset, int timeout = 10000)
        {
            throw new NotSupportedException("Http proxy does not support udp protocol.");
        }

        #endregion

        #region protected

        protected override Socket Connect(EndPoint remoteEP, Socket viaSocket)
        {
            try
            {
                string httpConnectRequest = "CONNECT " + remoteEP.ToString() + " HTTP/1.0\r\n";

                if (_credential != null)
                    httpConnectRequest += "Proxy-Authorization: Basic " + Convert.ToBase64String(Encoding.ASCII.GetBytes(_credential.UserName + ":" + _credential.Password)) + "\r\n";

                httpConnectRequest += "\r\n";

                viaSocket.Send(Encoding.ASCII.GetBytes(httpConnectRequest));

                byte[] buffer = new byte[128];
                int bytesRecv = viaSocket.Receive(buffer);

                if (bytesRecv < 1)
                    throw new HttpProxyException("No response was received from http proxy server.");

                string httpResponse = Encoding.ASCII.GetString(buffer, 0, bytesRecv);
                string[] httpResponseParts = httpResponse.Split('\r')[0].Split(new char[] { ' ' }, 3);

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

        #region properties

        public ICredentials Credentials
        {
            get { return _credential; }
            set { throw new NotImplementedException(); }
        }

        #endregion
    }
}
