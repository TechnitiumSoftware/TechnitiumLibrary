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

namespace TechnitiumLibrary.Net.Proxy
{
    public enum NetProxyType : byte
    {
        None = 0,
        Http = 1,
        Socks5 = 2
    }

    public class NetProxy
    {
        #region variables

        readonly NetProxyType _type;

        readonly WebProxyEx _httpProxy;
        readonly SocksClient _socksProxy;

        NetProxy _viaProxy;

        ICollection<NetProxyBypassItem> _proxyBypassList = new NetProxyBypassItem[] { new NetProxyBypassItem("127.0.0.0/8"), new NetProxyBypassItem("169.254.0.0/16"), new NetProxyBypassItem("fe80::/10"), new NetProxyBypassItem("::1"), new NetProxyBypassItem("localhost") };

        public readonly static NetProxy None = new NetProxy();

        bool _isUdpAvailableChecked;
        bool _isUdpAvailable;

        #endregion

        #region constructor

        public NetProxy(NetProxyType type, IPAddress address, int port, NetworkCredential credential = null)
               : this(type, new IPEndPoint(address, port), credential)
        { }

        public NetProxy(NetProxyType type, string address, int port, NetworkCredential credential = null)
            : this(type, IPAddress.TryParse(address, out IPAddress ipAddress) ? (EndPoint)new IPEndPoint(ipAddress, port) : new DomainEndPoint(address, port), credential)
        { }

        public NetProxy(NetProxyType type, EndPoint proxyEndPoint, NetworkCredential credential = null)
        {
            _type = type;

            switch (type)
            {
                case NetProxyType.Http:
                    _httpProxy = new WebProxyEx(new Uri("http://" + proxyEndPoint.GetAddress() + ":" + proxyEndPoint.GetPort()), false, new string[] { }, credential);
                    break;

                case NetProxyType.Socks5:
                    _socksProxy = new SocksClient(proxyEndPoint, credential);
                    break;

                default:
                    throw new NotSupportedException("Proxy type not supported.");
            }
        }

        public NetProxy(WebProxyEx httpProxy)
        {
            _type = NetProxyType.Http;
            _httpProxy = httpProxy;
        }

        public NetProxy(SocksClient socksProxy)
        {
            _type = NetProxyType.Socks5;
            _socksProxy = socksProxy;
        }

        private NetProxy()
        {
            _type = NetProxyType.None;
        }

        #endregion

        #region static

        public static NetProxy GetDefaultProxy()
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

            return new NetProxy(new WebProxyEx(proxyAddress) { Credentials = proxy.Credentials });
        }

        #endregion

        #region public

        public bool IsProxyBypassed(EndPoint remoteEP)
        {
            foreach (NetProxyBypassItem bypassItem in _proxyBypassList)
            {
                if (bypassItem.IsMatching(remoteEP))
                    return true;
            }

            return false;
        }

        public bool IsProxyAvailable()
        {
            switch (_type)
            {
                case NetProxyType.Http:
                    return _httpProxy.IsProxyAvailable();

                case NetProxyType.Socks5:
                    return _socksProxy.IsProxyAvailable();

                default:
                    return false;
            }
        }

        public void CheckProxyAccess()
        {
            switch (_type)
            {
                case NetProxyType.Http:
                    _httpProxy.CheckProxyAccess();
                    break;

                case NetProxyType.Socks5:
                    _socksProxy.CheckProxyAccess();
                    break;

                default:
                    throw new NotSupportedException("Proxy type not supported.");
            }
        }

        public bool IsUdpAvailable()
        {
            if (_isUdpAvailableChecked)
                return _isUdpAvailable;

            switch (_type)
            {
                case NetProxyType.Http:
                    _isUdpAvailable = false;
                    break;

                case NetProxyType.Socks5:
                    SocksUdpAssociateRequestHandler udpHandler = null;

                    try
                    {
                        udpHandler = _socksProxy.UdpAssociate();

                        _isUdpAvailable = true;
                    }
                    catch (SocksClientException ex)
                    {
                        if (ex.ReplyCode == SocksReplyCode.CommandNotSupported)
                            _isUdpAvailable = false;
                        else
                            throw;
                    }
                    finally
                    {
                        if (udpHandler != null)
                            udpHandler.Dispose();
                    }
                    break;

                default:
                    throw new NotSupportedException("Proxy type not supported.");
            }

            _isUdpAvailableChecked = true;

            return _isUdpAvailable;
        }

        public Socket Connect(string address, int port, int timeout = 10000)
        {
            EndPoint remoteEP;

            if (IPAddress.TryParse(address, out IPAddress ipAddr))
                remoteEP = new IPEndPoint(ipAddr, port);
            else
                remoteEP = new DomainEndPoint(address, port);

            return Connect(remoteEP, timeout);
        }

        public Socket Connect(EndPoint remoteEP, int timeout = 10000)
        {
            if (IsProxyBypassed(remoteEP))
            {
                IPEndPoint hostEP = remoteEP.GetIPEndPoint();
                Socket socket = new Socket(hostEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                IAsyncResult result = socket.BeginConnect(hostEP, null, null);
                if (!result.AsyncWaitHandle.WaitOne(timeout))
                    throw new SocketException((int)SocketError.TimedOut);

                if (!socket.Connected)
                    throw new SocketException((int)SocketError.ConnectionRefused);

                return socket;
            }

            Socket viaProxySocket = null;

            if (_viaProxy != null)
                viaProxySocket = _viaProxy.Connect(this.ProxyEndPoint, timeout);

            switch (_type)
            {
                case NetProxyType.Http:
                    if (viaProxySocket == null)
                        return _httpProxy.Connect(remoteEP, timeout);
                    else
                        return _httpProxy.Connect(remoteEP, viaProxySocket);

                case NetProxyType.Socks5:
                    if (viaProxySocket == null)
                        return _socksProxy.Connect(remoteEP, timeout);
                    else
                        return _socksProxy.Connect(remoteEP, viaProxySocket);

                default:
                    throw new NotSupportedException("Proxy type not supported.");
            }
        }

        public TunnelProxy CreateLocalTunnelProxy(string address, int port, int timeout = 10000, bool enableSsl = false, bool ignoreCertificateErrors = false)
        {
            EndPoint remoteEP;

            if (IPAddress.TryParse(address, out IPAddress ipAddr))
                remoteEP = new IPEndPoint(ipAddr, port);
            else
                remoteEP = new DomainEndPoint(address, port);

            return CreateLocalTunnelProxy(remoteEP, timeout, enableSsl, ignoreCertificateErrors);
        }

        public TunnelProxy CreateLocalTunnelProxy(EndPoint remoteEP, int timeout = 10000, bool enableSsl = false, bool ignoreCertificateErrors = false)
        {
            return new TunnelProxy(Connect(remoteEP, timeout), remoteEP, enableSsl, ignoreCertificateErrors);
        }

        public int UdpReceiveFrom(EndPoint remoteEP, byte[] request, byte[] response, int timeout = 10000)
        {
            return UdpReceiveFrom(remoteEP, request, 0, request.Length, response, 0, timeout);
        }

        public int UdpReceiveFrom(EndPoint remoteEP, byte[] request, int requestOffset, int requestSize, byte[] response, int responseOffset, int timeout = 10000)
        {
            if (IsProxyBypassed(remoteEP))
            {
                IPEndPoint hostEP = remoteEP.GetIPEndPoint();

                using (Socket socket = new Socket(hostEP.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
                {
                    socket.ReceiveTimeout = timeout;

                    //send request
                    socket.SendTo(request, requestOffset, requestSize, SocketFlags.None, hostEP);

                    //receive request
                    EndPoint ep;

                    if (hostEP.AddressFamily == AddressFamily.InterNetworkV6)
                        ep = new IPEndPoint(IPAddress.IPv6Any, 0);
                    else
                        ep = new IPEndPoint(IPAddress.Any, 0);

                    int bytesReceived;

                    do
                    {
                        bytesReceived = socket.ReceiveFrom(response, responseOffset, response.Length, SocketFlags.None, ref ep);
                    }
                    while (!hostEP.Equals(ep));

                    return bytesReceived;
                }
            }

            switch (_type)
            {
                case NetProxyType.Socks5:
                    if (_viaProxy != null)
                        throw new NotSupportedException("Cannot chain proxies for SOCKS5 Udp protocol.");

                    using (SocksUdpAssociateRequestHandler proxyUdpRequestHandler = _socksProxy.UdpAssociate(timeout))
                    {
                        proxyUdpRequestHandler.ReceiveTimeout = timeout;

                        //send request
                        proxyUdpRequestHandler.SendTo(request, requestOffset, requestSize, remoteEP);

                        //receive request
                        return proxyUdpRequestHandler.ReceiveFrom(response, responseOffset, response.Length - responseOffset, out EndPoint ep);
                    }

                default:
                    throw new NotSupportedException("Proxy type not supported.");
            }
        }

        #endregion

        #region properties

        public NetProxyType Type
        { get { return _type; } }

        public string Address
        {
            get
            {
                switch (_type)
                {
                    case NetProxyType.Http:
                        return _httpProxy.Address.Host;

                    case NetProxyType.Socks5:
                        if (_socksProxy.ProxyEndPoint.AddressFamily == AddressFamily.Unspecified)
                            return (_socksProxy.ProxyEndPoint as DomainEndPoint).Address;

                        return (_socksProxy.ProxyEndPoint as IPEndPoint).Address.ToString();

                    default:
                        throw new NotSupportedException("Proxy type not supported.");
                }
            }
        }

        public int Port
        {
            get
            {
                switch (_type)
                {
                    case NetProxyType.Http:
                        return _httpProxy.Address.Port;

                    case NetProxyType.Socks5:
                        if (_socksProxy.ProxyEndPoint.AddressFamily == AddressFamily.Unspecified)
                            return (_socksProxy.ProxyEndPoint as DomainEndPoint).Port;

                        return (_socksProxy.ProxyEndPoint as IPEndPoint).Port;

                    default:
                        throw new NotSupportedException("Proxy type not supported.");
                }
            }
        }

        public EndPoint ProxyEndPoint
        {
            get
            {
                switch (_type)
                {
                    case NetProxyType.Http:
                        return _httpProxy.ProxyEndPoint;

                    case NetProxyType.Socks5:
                        return _socksProxy.ProxyEndPoint;

                    default:
                        throw new NotSupportedException("Proxy type not supported.");
                }
            }
        }

        public NetworkCredential Credential
        {
            get
            {
                switch (_type)
                {
                    case NetProxyType.Http:
                        return _httpProxy.Credentials?.GetCredential(new Uri("http://www.google.com/"), "Basic");

                    case NetProxyType.Socks5:
                        return _socksProxy.Credential;

                    default:
                        throw new NotSupportedException("Proxy type not supported.");
                }
            }
        }

        public WebProxyEx HttpProxy
        { get { return _httpProxy; } }

        public SocksClient SocksProxy
        { get { return _socksProxy; } }

        public NetProxy ViaProxy
        {
            get { return _viaProxy; }
            set { _viaProxy = value; }
        }

        public ICollection<NetProxyBypassItem> ProxyBypassList
        {
            get
            {
                NetProxyBypassItem[] copy = new NetProxyBypassItem[_proxyBypassList.Count];
                _proxyBypassList.CopyTo(copy, 0);

                return copy;
            }
            set
            {
                NetProxyBypassItem[] copy = new NetProxyBypassItem[value.Count];
                value.CopyTo(copy, 0);

                _proxyBypassList = copy;
            }
        }

        #endregion
    }
}
