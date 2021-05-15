/*
Technitium Library
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.Proxy
{
    public class SocksProxyBindHandler : IProxyServerBindHandler, IDisposable
    {
        #region variables

        Socket _socket;

        readonly SocksProxyReplyCode _replyCode;
        readonly EndPoint _bindEP;

        EndPoint _remoteEP;

        #endregion

        #region constructor

        internal SocksProxyBindHandler(Socket socket, EndPoint bindEP)
        {
            _socket = socket;

            _replyCode = SocksProxyReplyCode.Succeeded;
            _bindEP = bindEP;
        }

        internal SocksProxyBindHandler(SocksProxyReplyCode replyCode)
        {
            _replyCode = replyCode;
            _bindEP = new IPEndPoint(IPAddress.Any, 0);
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        bool _disposed;

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_socket != null)
                {
                    try
                    {
                        if (_socket.Connected)
                            _socket.Shutdown(SocketShutdown.Both);
                    }
                    catch
                    { }

                    _socket.Dispose();
                }
            }

            _disposed = true;
        }

        #endregion

        #region public

        public async Task<Socket> AcceptAsync()
        {
            SocksProxyReply reply = await SocksProxyReply.ReadReplyAsync(new NetworkStream(_socket));
            if (!reply.IsVersionSupported)
                throw new SocksProxyException("Socks version 5 is not supported by the proxy server.");

            if (reply.ReplyCode != SocksProxyReplyCode.Succeeded)
                throw new SocksProxyException("Socks proxy server request failed: " + reply.ReplyCode.ToString(), reply.ReplyCode);

            _remoteEP = reply.BindEndPoint;

            Socket socket = _socket;
            _socket = null; //prevent socket from getting disposed

            return socket;
        }

        #endregion

        #region properties

        public SocksProxyReplyCode ReplyCode
        { get { return _replyCode; } }

        public EndPoint ProxyRemoteEndPoint
        { get { return _remoteEP; } }

        public EndPoint ProxyLocalEndPoint
        { get { return _bindEP; } }

        #endregion
    }
}
