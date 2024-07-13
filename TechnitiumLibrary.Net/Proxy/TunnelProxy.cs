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
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

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

        #endregion

        #region constructor

        public TunnelProxy(Socket remoteSocket, EndPoint remoteEP, bool enableSsl, bool ignoreCertificateErrors)
        {
            _remoteSocket = remoteSocket;
            _remoteEP = remoteEP;
            _enableSsl = enableSsl;
            _ignoreCertificateErrors = ignoreCertificateErrors;

            //start local tunnel
            IPEndPoint bindEP;

            if (_remoteSocket.AddressFamily == AddressFamily.InterNetworkV6)
                bindEP = new IPEndPoint(IPAddress.IPv6Loopback, 0);
            else
                bindEP = new IPEndPoint(IPAddress.Loopback, 0);

            _tunnelListener = new Socket(bindEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            _tunnelListener.NoDelay = true;
            _tunnelListener.Bind(bindEP);
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
            GC.SuppressFinalize(this);
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
            }

            _disposed = true;
        }

        #endregion

        #region static

        public static async Task<TunnelProxy> CreateTunnelProxyAsync(EndPoint remoteEP, bool enableSsl, bool ignoreCertificateErrors, CancellationToken cancellationToken = default)
        {
            IPEndPoint ep = await remoteEP.GetIPEndPointAsync(cancellationToken: cancellationToken);

            Socket socket = new Socket(ep.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(ep, cancellationToken);

            socket.NoDelay = true;

            return new TunnelProxy(socket, remoteEP, enableSsl, ignoreCertificateErrors);
        }

        #endregion

        #region private

        private async Task AcceptTunnelConnectionAsync()
        {
            try
            {
                _tunnelSocket = await TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                {
                    return _tunnelListener.AcceptAsync(cancellationToken1).AsTask();
                }, TUNNEL_WAIT_TIMEOUT);

                _tunnelListener.Dispose();

                Stream remoteStream = new NetworkStream(_remoteSocket);

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
                        sslStream = new SslStream(remoteStream);
                    }

                    await TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                    {
                        return sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions() { TargetHost = _remoteEP.GetAddress() }, cancellationToken1);
                    }, TUNNEL_WAIT_TIMEOUT);

                    remoteStream = sslStream;
                }

                Stream tunnelStream = new NetworkStream(_tunnelSocket);

                _ = remoteStream.CopyToAsync(tunnelStream).ContinueWith(delegate (Task prevTask) { Dispose(); });
                _ = tunnelStream.CopyToAsync(remoteStream).ContinueWith(delegate (Task prevTask) { Dispose(); });
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
