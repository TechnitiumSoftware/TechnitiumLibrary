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
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Proxy
{
    public enum NetProxyType : byte
    {
        None = 0,
        Http = 1,
        Socks5 = 2
    }

    public abstract class NetProxy : IWebProxy, IProxyServerConnectionManager
    {
        #region variables

        readonly NetProxyType _type;

        protected readonly EndPoint _proxyEP;
        protected readonly NetworkCredential _credential;

        protected NetProxy _viaProxy;
        ICollection<NetProxyBypassItem> _bypassList = new List<NetProxyBypassItem> { new NetProxyBypassItem("127.0.0.0/8"), new NetProxyBypassItem("169.254.0.0/16"), new NetProxyBypassItem("fe80::/10"), new NetProxyBypassItem("::1"), new NetProxyBypassItem("localhost") };

        HttpProxyServer _httpProxyServer;

        #endregion

        #region constructor

        protected NetProxy(NetProxyType type, EndPoint proxyEP, NetworkCredential credential = null)
        {
            _type = type;
            _proxyEP = proxyEP;
            _credential = credential;
        }

        #endregion

        #region static

        public static NetProxy CreateHttpProxy(string address, int port = 8080, NetworkCredential credential = null)
        {
            return new HttpProxy(EndPointExtension.GetEndPoint(address, port), credential);
        }

        public static NetProxy CreateHttpProxy(EndPoint proxyEP, NetworkCredential credential = null)
        {
            return new HttpProxy(proxyEP, credential);
        }

        public static NetProxy CreateSystemHttpProxy()
        {
            IWebProxy proxy = WebRequest.DefaultWebProxy;
            if (proxy == null)
                return null; //no proxy configured

            Uri testUri = new Uri("https://www.google.com/");

            if (proxy.IsBypassed(testUri))
                return null; //no proxy configured

            Uri proxyAddress = proxy.GetProxy(testUri);
            if (proxyAddress.Equals(testUri))
                return null; //no proxy configured

            return new HttpProxy(EndPointExtension.GetEndPoint(proxyAddress.Host, proxyAddress.Port), proxy.Credentials.GetCredential(proxyAddress, "BASIC"));
        }

        public static NetProxy CreateSocksProxy(string address, int port = 1080, NetworkCredential credential = null)
        {
            return new SocksProxy(EndPointExtension.GetEndPoint(address, port), credential);
        }

        public static NetProxy CreateSocksProxy(EndPoint proxyEP, NetworkCredential credential = null)
        {
            return new SocksProxy(proxyEP, credential);
        }

        public static NetProxy CreateProxy(NetProxyType type, string address, int port, NetworkCredential credential = null)
        {
            switch (type)
            {
                case NetProxyType.Http:
                    return new HttpProxy(EndPointExtension.GetEndPoint(address, port), credential);

                case NetProxyType.Socks5:
                    return new SocksProxy(EndPointExtension.GetEndPoint(address, port), credential);

                default:
                    throw new NotSupportedException("Proxy type not supported.");
            }
        }

        public static NetProxy CreateProxy(NetProxyType type, EndPoint proxyEP, NetworkCredential credential = null)
        {
            switch (type)
            {
                case NetProxyType.Http:
                    return new HttpProxy(proxyEP, credential);

                case NetProxyType.Socks5:
                    return new SocksProxy(proxyEP, credential);

                default:
                    throw new NotSupportedException("Proxy type not supported.");
            }
        }

        #endregion

        #region protected

        protected static async Task<Socket> GetTcpConnectionAsync(EndPoint ep)
        {
            if (ep.AddressFamily == AddressFamily.Unspecified)
                ep = await ep.GetIPEndPointAsync();

            Socket socket = new Socket(ep.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            await socket.ConnectAsync(ep);

            socket.NoDelay = true;

            return socket;
        }

        protected abstract Task<Socket> ConnectAsync(EndPoint remoteEP, Socket viaSocket);

        #endregion

        #region public

        public virtual Uri GetProxy(Uri destination)
        {
            if (IsBypassed(destination))
                return destination;

            if (_httpProxyServer == null)
                _httpProxyServer = new HttpProxyServer(this);

            return new Uri("http://" + _httpProxyServer.LocalEndPoint.ToString());
        }

        public bool IsBypassed(Uri host)
        {
            return IsBypassed(EndPointExtension.GetEndPoint(host.Host, host.Port));
        }

        public bool IsBypassed(EndPoint ep)
        {
            foreach (NetProxyBypassItem bypassItem in _bypassList)
            {
                if (bypassItem.IsMatching(ep))
                    return true;
            }

            return false;
        }

        public async Task<bool> IsProxyAccessibleAsync(bool throwException = false, int timeout = 10000)
        {
            try
            {
                using (Socket socket = await GetTcpConnectionAsync(_proxyEP).WithTimeout(timeout))
                { }

                return true;
            }
            catch
            {
                if (throwException)
                    throw;

                return false;
            }
        }

        public abstract Task<bool> IsUdpAvailableAsync();

        public async Task<Socket> ConnectAsync(string address, int port)
        {
            return await ConnectAsync(EndPointExtension.GetEndPoint(address, port));
        }

        public async Task<Socket> ConnectAsync(EndPoint remoteEP)
        {
            if (IsBypassed(remoteEP))
                return await GetTcpConnectionAsync(remoteEP);

            if (_viaProxy == null)
                return await ConnectAsync(remoteEP, await GetTcpConnectionAsync(_proxyEP));
            else
                return await ConnectAsync(remoteEP, await _viaProxy.ConnectAsync(_proxyEP));
        }

        public Task<TunnelProxy> CreateTunnelProxyAsync(string address, int port, bool enableSsl = false, bool ignoreCertificateErrors = false)
        {
            return CreateTunnelProxyAsync(EndPointExtension.GetEndPoint(address, port), enableSsl, ignoreCertificateErrors);
        }

        public async Task<TunnelProxy> CreateTunnelProxyAsync(EndPoint remoteEP, bool enableSsl = false, bool ignoreCertificateErrors = false)
        {
            return new TunnelProxy(await ConnectAsync(remoteEP), remoteEP, enableSsl, ignoreCertificateErrors);
        }

        public Task<int> UdpQueryAsync(byte[] request, byte[] response, EndPoint remoteEP, int timeout = 10000, int retries = 1, bool expBackoffTimeout = false, CancellationToken cancellationToken = default)
        {
            return UdpQueryAsync(request, 0, request.Length, response, 0, response.Length, remoteEP, timeout, retries, expBackoffTimeout, cancellationToken);
        }

        public abstract Task<int> UdpQueryAsync(byte[] request, int requestOffset, int requestCount, byte[] response, int responseOffset, int responseCount, EndPoint remoteEP, int timeout = 10000, int retries = 1, bool expBackoffTimeout = false, CancellationToken cancellationToken = default);

        #endregion

        #region properties

        public NetProxyType Type
        { get { return _type; } }

        public EndPoint ProxyEndPoint
        { get { return _proxyEP; } }

        public string Address
        { get { return _proxyEP.GetAddress(); } }

        public int Port
        { get { return _proxyEP.GetPort(); } }

        public NetworkCredential Credential
        { get { return _credential; } }

        ICredentials IWebProxy.Credentials
        {
            get { return _credential; }
            set { throw new NotImplementedException(); }
        }

        public NetProxy ViaProxy
        {
            get { return _viaProxy; }
            set { _viaProxy = value; }
        }

        public ICollection<NetProxyBypassItem> BypassList
        {
            get { return _bypassList; }
            set { _bypassList = value; }
        }

        #endregion
    }
}
