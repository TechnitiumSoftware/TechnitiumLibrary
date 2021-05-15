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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.Proxy
{
    public enum TransparentProxyServerMethod
    {
        DNAT = 1, //iptables -t nat -A PREROUTING -i ens32 -p tcp -j DNAT --to <proxy-interface-address-not-loopback>:<proxy-port>
        TPROXY = 2 //follow SQUID docs https://wiki.squid-cache.org/Features/Tproxy4
    }

    public class TransparentProxyServer : IDisposable
    {
        #region variables

        const int SOL_IP = 0;
        const int SO_ORIGINAL_DST = 80;
        const int IPPROTO_IP = 0;
        const int IP_TRANSPARENT = 19;

        readonly IPEndPoint _localEP;
        readonly IProxyServerConnectionManager _connectionManager;
        readonly TransparentProxyServerMethod _method;

        readonly Socket _listener;
        readonly ConcurrentDictionary<ProxyServerSession, object> _sessions = new ConcurrentDictionary<ProxyServerSession, object>();

        #endregion

        #region constructors

        public TransparentProxyServer(IProxyServerConnectionManager connectionManager = null, TransparentProxyServerMethod method = TransparentProxyServerMethod.DNAT, int backlog = 10)
            : this(new IPEndPoint(IPAddress.Any, 8081), connectionManager, method, backlog)
        { }

        public TransparentProxyServer(IPEndPoint localEP, IProxyServerConnectionManager connectionManager = null, TransparentProxyServerMethod method = TransparentProxyServerMethod.DNAT, int backlog = 10)
        {
            if (Environment.OSVersion.Platform != PlatformID.Unix)
                throw new NotSupportedException("Only Unix/Linux is supported.");

            if ((method == TransparentProxyServerMethod.DNAT) && (localEP.AddressFamily != AddressFamily.InterNetwork))
                throw new NotSupportedException("Only IPv4 is supported with DNAT.");

            _listener = new Socket(localEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            if (method == TransparentProxyServerMethod.TPROXY)
            {
                _listener.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1);
                _listener.SetRawSocketOption(IPPROTO_IP, IP_TRANSPARENT, new byte[] { 1 });
            }

            _listener.Bind(localEP);
            _listener.Listen(backlog);
            _listener.NoDelay = true;

            _localEP = (IPEndPoint)_listener.LocalEndPoint;
            _connectionManager = connectionManager;
            _method = method;

            if (_connectionManager == null)
                _connectionManager = new DefaultProxyServerConnectionManager();

            //accept requests async
            int tasks = Math.Max(1, Environment.ProcessorCount);
            for (int i = 0; i < tasks; i++)
                _ = Task.Factory.StartNew(AcceptRequestAsync, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current);
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_listener != null)
                    _listener.Dispose();

                foreach (KeyValuePair<ProxyServerSession, object> session in _sessions)
                    session.Key.Dispose();

                _sessions.Clear();
            }

            _disposed = true;
        }

        #endregion

        #region private

        private async Task AcceptRequestAsync()
        {
            try
            {
                while (true)
                {
                    Socket socket = await _listener.AcceptAsync();

                    ProxyServerSession session = new ProxyServerSession(socket, _connectionManager, _method);

                    session.Disposed += delegate (object sender, EventArgs e)
                    {
                        _sessions.TryRemove(sender as ProxyServerSession, out _);
                    };

                    if (_sessions.TryAdd(session, null))
                        _ = session.StartAsync();
                }
            }
            finally
            {
                Dispose();
            }
        }

        #endregion

        #region properties

        public IPEndPoint LocalEndPoint
        { get { return _localEP; } }

        #endregion

        class ProxyServerSession : IDisposable
        {
            #region events

            public event EventHandler Disposed;

            #endregion

            #region variables

            readonly Socket _localSocket;
            readonly IProxyServerConnectionManager _connectionManager;
            readonly TransparentProxyServerMethod _method;

            Socket _remoteSocket;

            #endregion

            #region constructor

            public ProxyServerSession(Socket localSocket, IProxyServerConnectionManager connectionManager, TransparentProxyServerMethod method)
            {
                _localSocket = localSocket;
                _connectionManager = connectionManager;
                _method = method;
            }

            #endregion

            #region IDisposable

            bool _disposed;
            readonly object _disposeLock = new object();

            public void Dispose()
            {
                Dispose(true);
            }

            protected virtual void Dispose(bool disposing)
            {
                lock (_disposeLock)
                {
                    if (_disposed)
                        return;

                    if (disposing)
                    {
                        if (_localSocket != null)
                            _localSocket.Dispose();

                        if (_remoteSocket != null)
                            _remoteSocket.Dispose();
                    }

                    _disposed = true;
                    Disposed?.Invoke(this, EventArgs.Empty);
                }
            }

            #endregion

            #region private

            private IPEndPoint GetOriginalDestination()
            {
                try
                {
                    switch (_method)
                    {
                        case TransparentProxyServerMethod.DNAT:
                            byte[] buffer = new byte[32];
                            int retVal = _localSocket.GetRawSocketOption(SOL_IP, SO_ORIGINAL_DST, buffer);
                            if (retVal > 0)
                            {
                                AddressFamily af = (AddressFamily)BitConverter.ToUInt16(buffer, 0);
                                switch (af)
                                {
                                    case AddressFamily.InterNetwork:
                                        {
                                            Array.Reverse(buffer, 2, 2);
                                            int port = BitConverter.ToUInt16(buffer, 2);
                                            IPAddress address = new IPAddress(new Span<byte>(buffer, 4, 4));

                                            return new IPEndPoint(address, port);
                                        }

                                    case AddressFamily.InterNetworkV6:
                                        {
                                            Array.Reverse(buffer, 2, 2);
                                            int port = BitConverter.ToUInt16(buffer, 2);
                                            IPAddress address = new IPAddress(new Span<byte>(buffer, 4, 16));

                                            return new IPEndPoint(address, port);
                                        }
                                }
                            }
                            break;

                        case TransparentProxyServerMethod.TPROXY:
                            return _localSocket.LocalEndPoint as IPEndPoint;
                    }
                }
                catch
                { }

                return null;
            }

            #endregion

            #region public

            public async Task StartAsync()
            {
                bool dontDispose = false;

                try
                {
                    IPEndPoint originalDestinationEP = GetOriginalDestination();
                    if (originalDestinationEP == null)
                        return;

                    _remoteSocket = await _connectionManager.ConnectAsync(originalDestinationEP);

                    //pipe sockets
                    _ = _localSocket.PipeToAsync(_remoteSocket).ContinueWith(delegate (Task prevTask) { Dispose(); });
                    dontDispose = true;
                }
                finally
                {
                    if (!dontDispose)
                        Dispose();
                }
            }

            #endregion
        }
    }
}
