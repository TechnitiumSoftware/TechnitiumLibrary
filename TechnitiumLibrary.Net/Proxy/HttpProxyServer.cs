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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Http;

namespace TechnitiumLibrary.Net.Proxy
{
    public class HttpProxyServer : IDisposable
    {
        #region variables

        const int CLIENT_REQUEST_TIMEOUT = 30000;

        readonly IPEndPoint _localEP;
        readonly IProxyServerConnectionManager _connectionManager;
        readonly IProxyServerAuthenticationManager _authenticationManager;

        readonly Socket _listener;
        readonly ConcurrentDictionary<ProxyServerSession, object> _sessions = new ConcurrentDictionary<ProxyServerSession, object>();

        #endregion

        #region constructors

        public HttpProxyServer(IProxyServerConnectionManager connectionManager = null, IProxyServerAuthenticationManager authenticationManager = null, int backlog = 10)
            : this(new IPEndPoint(IPAddress.Loopback, 0), connectionManager, authenticationManager, backlog)
        { }

        public HttpProxyServer(IPEndPoint localEP, IProxyServerConnectionManager connectionManager = null, IProxyServerAuthenticationManager authenticationManager = null, int backlog = 10)
        {
            _listener = new Socket(localEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            _listener.Bind(localEP);
            _listener.Listen(backlog);
            _listener.NoDelay = true;

            _localEP = (IPEndPoint)_listener.LocalEndPoint;
            _connectionManager = connectionManager;
            _authenticationManager = authenticationManager;

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
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_listener != null)
                    _listener.Dispose();

                foreach (ProxyServerSession session in _sessions.Keys)
                    session.Dispose();

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

                    ProxyServerSession session = new ProxyServerSession(socket, _connectionManager, _authenticationManager);

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
            readonly IProxyServerAuthenticationManager _authenticationManager;

            Socket _remoteSocket;

            #endregion

            #region constructor

            public ProxyServerSession(Socket localSocket, IProxyServerConnectionManager connectionManager, IProxyServerAuthenticationManager authenticationManager)
            {
                _localSocket = localSocket;
                _connectionManager = connectionManager;
                _authenticationManager = authenticationManager;
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

            private async Task DoConnectAsync(NetworkStream localStream, HttpRequest httpRequest)
            {
                string host;
                int port;
                {
                    string[] parts = httpRequest.RequestPath.Split(':');

                    host = parts[0];

                    if (parts.Length > 1)
                        port = int.Parse(parts[1]);
                    else
                        port = 80;
                }

                //connect to remote server
                _remoteSocket = await _connectionManager.ConnectAsync(EndPointExtension.GetEndPoint(host, port));

                //signal client 200 OK
                await localStream.WriteAsync(Encoding.ASCII.GetBytes(httpRequest.Protocol + " 200 OK\r\nConnection: close\r\n\r\n"));

                //pipe sockets
                _ = _localSocket.PipeToAsync(_remoteSocket).ContinueWith(delegate (Task prevTask) { Dispose(); });
            }

            private Task SendResponseAsync(Exception ex)
            {
                string content = "<h1>500 Internal Server Error</h1>";

                if (!string.IsNullOrEmpty(ex.Message))
                    content += "<p>" + ex.Message + "</p>";

                if (Debugger.IsAttached)
                    content += "<p>" + ex.ToString() + "</p>";

                return SendResponseAsync(500, content);
            }

            private async Task SendResponseAsync(int statusCode, string content)
            {
                string statusString;
                {
                    StringBuilder sb = new StringBuilder();

                    foreach (char c in ((HttpStatusCode)statusCode).ToString().ToCharArray())
                    {
                        if (char.IsUpper(c) && sb.Length > 0)
                            sb.Append(' ');

                        sb.Append(c);
                    }

                    statusString = statusCode + " " + sb.ToString();
                }

                string response = "HTTP/1.1 " + statusCode + " " + statusString + "\r\nDate: " + DateTime.UtcNow.ToString("R") + "\r\nConnection: close\r\nContent-Type: text/html\r\nContent-Length: " + content.Length + "\r\n\r\n" + content;

                try
                {
                    if (_localSocket.Connected)
                        await _localSocket.SendAsync(Encoding.ASCII.GetBytes(response), SocketFlags.None);
                }
                catch
                { }
            }

            #endregion

            #region public

            public async Task StartAsync()
            {
                bool dontDispose = false;

                try
                {
                    NetworkStream localStream = new NetworkStream(_localSocket);
                    Stream remoteStream = null;

                    string lastHost = null;
                    int lastPort = 0;

                    while (true)
                    {
                        HttpRequest httpRequest;
                        {
                            Task<HttpRequest> task = HttpRequest.ReadRequestAsync(localStream);

                            if (remoteStream == null)
                            {
                                //wait for timeout only for initial request to avoid causing timeout to close existing data stream
                                using (CancellationTokenSource timeoutCancellationTokenSource = new CancellationTokenSource())
                                {
                                    if (await Task.WhenAny(task, Task.Delay(CLIENT_REQUEST_TIMEOUT, timeoutCancellationTokenSource.Token)) != task)
                                        return; //request timed out

                                    timeoutCancellationTokenSource.Cancel(); //cancel delay task
                                }
                            }

                            httpRequest = await task;
                        }

                        if (httpRequest == null)
                            return; //connection closed gracefully by client

                        if (_authenticationManager != null)
                        {
                            string proxyAuth = httpRequest.Headers[HttpRequestHeader.ProxyAuthorization];
                            if (string.IsNullOrEmpty(proxyAuth))
                            {
                                await SendResponseAsync(407, "<h1>Proxy Authentication Required</h1>");
                                return;
                            }

                            string username;
                            string password;
                            {
                                string[] parts = proxyAuth.Split(new char[] { ' ' }, 2);

                                if (!parts[0].Equals("BASIC", StringComparison.OrdinalIgnoreCase) || (parts.Length < 2))
                                {
                                    await SendResponseAsync(407, "<h1>Proxy Authentication Required</h1><p>Proxy authentication method is not supported.</p>");
                                    return;
                                }

                                string[] credParts = Encoding.ASCII.GetString(Convert.FromBase64String(parts[1])).Split(new char[] { ':' }, 2);
                                if (credParts.Length != 2)
                                {
                                    await SendResponseAsync(407, "<h1>Proxy Authentication Required</h1><p>Proxy authentication method is not supported.</p>");
                                    return;
                                }

                                username = credParts[0];
                                password = credParts[1];
                            }

                            if (!_authenticationManager.Authenticate(username, password))
                            {
                                await SendResponseAsync(407, "<h1>Proxy Authentication Required</h1><p>Invalid username or password.</p>");
                                return;
                            }
                        }

                        if (httpRequest.HttpMethod.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
                        {
                            await DoConnectAsync(localStream, httpRequest);
                            dontDispose = true;
                            break;
                        }
                        else
                        {
                            #region connect to remote server

                            string host;
                            int port;
                            string requestPathAndQuery;

                            if (Uri.TryCreate(httpRequest.RequestPathAndQuery, UriKind.Absolute, out Uri requestUri))
                            {
                                host = requestUri.Host;
                                port = requestUri.Port;
                                requestPathAndQuery = requestUri.PathAndQuery;
                            }
                            else
                            {
                                string hostHeader = httpRequest.Headers[HttpRequestHeader.Host];
                                if (string.IsNullOrEmpty(hostHeader))
                                    throw new HttpProxyServerException("Invalid proxy request.");

                                string[] parts = hostHeader.Split(':');

                                host = parts[0];

                                if (parts.Length > 1)
                                    port = int.Parse(parts[1]);
                                else
                                    port = 80;

                                requestPathAndQuery = httpRequest.RequestPathAndQuery;
                            }

                            if (!host.Equals(lastHost) || port != lastPort || !_remoteSocket.Connected)
                            {
                                if (_remoteSocket != null)
                                {
                                    if (_remoteSocket.Connected)
                                    {
                                        try
                                        {
                                            _remoteSocket.Shutdown(SocketShutdown.Both);
                                        }
                                        catch
                                        { }
                                    }

                                    _remoteSocket.Dispose();
                                }

                                _remoteSocket = await _connectionManager.ConnectAsync(EndPointExtension.GetEndPoint(host, port));
                                remoteStream = new WriteBufferedStream(new NetworkStream(_remoteSocket), 512);

                                lastHost = host;
                                lastPort = port;

                                //copy remote socket to local socket
                                _ = _remoteSocket.CopyToAsync(_localSocket).ContinueWith(delegate (Task prevTask)
                                {
                                    try
                                    {
                                        if ((prevTask.Status == TaskStatus.RanToCompletion) && _localSocket.Connected)
                                            _localSocket.Shutdown(SocketShutdown.Both);
                                    }
                                    finally
                                    {
                                        Dispose();
                                    }
                                });
                            }

                            #endregion

                            #region relay client request to server

                            foreach (string header in httpRequest.Headers.AllKeys)
                            {
                                if (header.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase))
                                    httpRequest.Headers.Remove(header);
                            }

                            await remoteStream.WriteAsync(Encoding.ASCII.GetBytes(httpRequest.HttpMethod + " " + requestPathAndQuery + " " + httpRequest.Protocol + "\r\n"));
                            await remoteStream.WriteAsync(httpRequest.Headers.ToByteArray());

                            if (httpRequest.InputStream != null)
                                await httpRequest.InputStream.CopyToAsync(remoteStream);

                            await remoteStream.FlushAsync();

                            #endregion
                        }
                    }
                }
                catch (Exception ex)
                {
                    await SendResponseAsync(ex);
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
