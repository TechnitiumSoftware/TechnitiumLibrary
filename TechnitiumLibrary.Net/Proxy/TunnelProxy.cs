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
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Proxy
{
    public class TunnelProxy : IDisposable
    {
        #region variables

        const int TUNNEL_WAIT_TIMEOUT = 10000;

        readonly Socket _remoteSocket;
        readonly EndPoint _remoteEP;
        readonly bool _enableSsl;
        readonly bool _ignoreCertificateErrors;

        readonly Socket _tunnelListener;
        readonly IPEndPoint _tunnelEP;
        Socket _tunnelSocket;
        Joint _tunnelJoint;

        #endregion

        #region constructor

        internal TunnelProxy(Socket remoteSocket, EndPoint remoteEP, bool enableSsl, bool ignoreCertificateErrors)
        {
            _remoteSocket = remoteSocket;
            _remoteEP = remoteEP;
            _enableSsl = enableSsl;
            _ignoreCertificateErrors = ignoreCertificateErrors;

            //start local tunnel
            _tunnelListener = new Socket(_remoteEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            if (_remoteEP.AddressFamily == AddressFamily.InterNetworkV6)
                _tunnelListener.Bind(new IPEndPoint(IPAddress.IPv6Loopback, 0));
            else
                _tunnelListener.Bind(new IPEndPoint(IPAddress.Loopback, 0));

            _tunnelListener.Listen(1);

            _tunnelEP = _tunnelListener.LocalEndPoint as IPEndPoint;

            //accept tunnel connection async
            _ = AcceptTunnelConnectionAsync();
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
                if (_remoteSocket != null)
                {
                    try
                    {
                        if (_remoteSocket.Connected)
                            _remoteSocket.Shutdown(SocketShutdown.Both);
                    }
                    catch
                    { }

                    _remoteSocket.Dispose();
                }

                if (_tunnelListener != null)
                    _tunnelListener.Dispose();

                if (_tunnelSocket != null)
                {
                    try
                    {
                        if (_tunnelSocket.Connected)
                            _tunnelSocket.Shutdown(SocketShutdown.Both);
                    }
                    catch
                    { }

                    _tunnelSocket.Dispose();
                }

                if (_tunnelJoint != null)
                    _tunnelJoint.Dispose();
            }

            _disposed = true;
        }

        #endregion

        #region private

        private async Task AcceptTunnelConnectionAsync()
        {
            try
            {
                _tunnelSocket = await _tunnelListener.AcceptAsync().WithTimeout(TUNNEL_WAIT_TIMEOUT);
                _tunnelListener.Dispose();

                Stream remoteStream = new NetworkStream(_remoteSocket, true);

                if (_enableSsl)
                {
                    SslStream sslStream;

                    if (_ignoreCertificateErrors)
                    {
                        sslStream = new SslStream(remoteStream, false, delegate (object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
                        {
                            return true; //ignore cert errors
                        });
                    }
                    else
                    {
                        sslStream = new SslStream(remoteStream, false);
                    }

                    string targetHost;

                    switch (_remoteEP.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                        case AddressFamily.InterNetworkV6:
                            targetHost = (_remoteEP as IPEndPoint).Address.ToString();
                            break;

                        case AddressFamily.Unspecified:
                            targetHost = (_remoteEP as DomainEndPoint).Address;
                            break;

                        default:
                            throw new NotSupportedException("AddressFamily not supported.");
                    }

                    await sslStream.AuthenticateAsClientAsync(targetHost).WithTimeout(TUNNEL_WAIT_TIMEOUT);

                    remoteStream = sslStream;
                }

                _tunnelJoint = new Joint(remoteStream, new NetworkStream(_tunnelSocket, true));

                _tunnelJoint.Disposing += delegate (object sender, EventArgs e)
                {
                    Dispose();
                };

                _tunnelJoint.Start();
            }
            catch
            {
                Dispose();
            }
        }

        #endregion

        #region properties

        public EndPoint RemoteEndPoint
        { get { return _remoteEP; } }

        public IPEndPoint TunnelEndPoint
        { get { return _tunnelEP; } }

        public bool IsBroken
        { get { return _disposed; } }

        #endregion
    }
}
