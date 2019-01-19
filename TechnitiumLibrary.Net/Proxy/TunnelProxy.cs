/*
Technitium Library
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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
using System.Text;
using System.Threading;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Proxy
{
    public class TunnelProxy : IDisposable
    {
        #region variables

        const int TUNNEL_WAIT_TIMEOUT = 10000;

        Socket _socket;
        EndPoint _remoteEP;
        readonly bool _enableSsl;
        readonly bool _ignoreCertificateErrors;

        bool _emulateHttpProxy;
        Socket _tunnelSocketListener;
        IPEndPoint _tunnelEP;
        Timer _tunnelWaitTimeoutTimer;
        Joint _tunnelJoint;

        #endregion

        #region constructor

        internal TunnelProxy(Socket socket, EndPoint remoteEP, bool enableSsl, bool ignoreCertificateErrors)
        {
            _socket = socket;
            _remoteEP = remoteEP;
            _enableSsl = enableSsl;
            _ignoreCertificateErrors = ignoreCertificateErrors;

            //start local tunnel
            _tunnelSocketListener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _tunnelSocketListener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _tunnelSocketListener.Listen(1);

            _tunnelEP = _tunnelSocketListener.LocalEndPoint as IPEndPoint;

            ThreadPool.QueueUserWorkItem(AcceptTunnelConnectionAsync);
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            Dispose(true);
        }

        bool _disposed = false;

        private void Dispose(bool disposing)
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

                if (_tunnelSocketListener != null)
                    _tunnelSocketListener.Dispose();

                if (_tunnelWaitTimeoutTimer != null)
                    _tunnelWaitTimeoutTimer.Dispose();

                if (_tunnelJoint != null)
                    _tunnelJoint.Dispose();
            }

            _disposed = true;
        }

        #endregion

        #region private

        private void AcceptTunnelConnectionAsync(object state)
        {
            try
            {
                _tunnelWaitTimeoutTimer = new Timer(delegate (object state2)
                {
                    try
                    {
                        if (_tunnelSocketListener != null)
                            Dispose();
                    }
                    catch
                    { }
                }, null, TUNNEL_WAIT_TIMEOUT, Timeout.Infinite);

                Socket tunnelSocket = _tunnelSocketListener.Accept();

                _tunnelWaitTimeoutTimer.Dispose();
                _tunnelWaitTimeoutTimer = null;

                _tunnelSocketListener.Dispose();
                _tunnelSocketListener = null;

                if (_emulateHttpProxy)
                {
                    byte[] proxyRequest = new byte[128];

                    do
                    {
                        tunnelSocket.Receive(proxyRequest);
                    }
                    while (tunnelSocket.Available > 0);

                    byte[] proxyResponse = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
                    tunnelSocket.Send(proxyResponse);
                }

                Stream stream = new NetworkStream(_socket, true);

                if (_enableSsl)
                {
                    SslStream sslStream;

                    if (_ignoreCertificateErrors)
                    {
                        sslStream = new SslStream(stream, false, delegate (object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
                        {
                            return true; //ignore cert errors
                        });
                    }
                    else
                    {
                        sslStream = new SslStream(stream, false);
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

                    sslStream.AuthenticateAsClient(targetHost);

                    stream = sslStream;
                }

                _tunnelJoint = new Joint(stream, new NetworkStream(tunnelSocket, true), delegate (object state2)
                {
                    this.Dispose();
                });
                _tunnelJoint.Start();

                _socket = null;
            }
            catch
            {
                this.Dispose();
            }
        }

        #endregion

        #region public

        public WebProxy EmulateHttpProxy()
        {
            _emulateHttpProxy = true;
            return new WebProxy(_tunnelEP.Address.ToString(), _tunnelEP.Port);
        }

        #endregion

        #region properties

        public EndPoint RemoteEndPoint
        { get { return _remoteEP; } }

        public IPEndPoint TunnelEndPoint
        { get { return _tunnelEP; } }

        public bool Disposed
        { get { return _disposed; } }

        #endregion
    }
}
