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

namespace TechnitiumLibrary.Net.Proxy
{
    public class SocksBindRequestHandler : IDisposable
    {
        #region variables

        readonly Socket _socket;
        readonly EndPoint _bindEP;

        EndPoint _dstEP;

        #endregion

        #region constructor

        internal SocksBindRequestHandler(Socket socket, EndPoint bindEP)
        {
            _socket = socket;
            _bindEP = bindEP;
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            Dispose(true);
        }

        bool _disposed = false;

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_socket != null)
                {
                    _socket.Shutdown(SocketShutdown.Both);
                    _socket.Dispose();
                }
            }

            _disposed = true;
        }

        #endregion

        #region public

        public Socket Accept()
        {
            byte[] response = new byte[262];

            if (_socket.Receive(response) < 10)
                throw new SocksProxyException("The connection was reset by the remote peer.");

            if (response[0] != SocksProxy.SOCKS_VERSION)
                throw new SocksProxyException("Socks version 5 is not supported by the proxy server.");

            SocksReplyCode reply = (SocksReplyCode)response[1];

            if (reply != SocksReplyCode.Succeeded)
                throw new SocksProxyException("Socks proxy server request failed: " + reply.ToString());

            _dstEP = SocksProxy.ParseEndpoint(response, 3);

            return _socket;
        }

        #endregion

        #region properties

        public EndPoint ProxyRemoteEndPoint
        { get { return _dstEP; } }

        public EndPoint ProxyLocalEndPoint
        { get { return _bindEP; } }

        #endregion
    }
}
