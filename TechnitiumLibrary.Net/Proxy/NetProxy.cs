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

    public abstract class NetProxy
    {
        #region variables

        readonly NetProxyType _type;

        protected EndPoint _proxyEP;
        protected NetworkCredential _credential;

        protected NetProxy _viaProxy;
        ICollection<NetProxyBypassItem> _bypassList = new List<NetProxyBypassItem> { new NetProxyBypassItem("127.0.0.0/8"), new NetProxyBypassItem("169.254.0.0/16"), new NetProxyBypassItem("fe80::/10"), new NetProxyBypassItem("::1"), new NetProxyBypassItem("localhost") };

        #endregion

        #region constructor

        protected NetProxy(NetProxyType type, EndPoint proxyEP, NetworkCredential credential)
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

        public static NetProxy CreateProxy(NetProxyType type, string address, int port, NetworkCredential credential)
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

        #endregion

        #region protected

        protected static Socket GetTcpConnection(EndPoint ep, int timeout)
        {
            IPEndPoint hostEP = ep.GetIPEndPoint();
            Socket socket = new Socket(hostEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            IAsyncResult result = socket.BeginConnect(hostEP, null, null);
            if (!result.AsyncWaitHandle.WaitOne(timeout))
                throw new SocketException((int)SocketError.TimedOut);

            if (!socket.Connected)
                throw new SocketException((int)SocketError.ConnectionRefused);

            socket.SendTimeout = timeout;
            socket.ReceiveTimeout = timeout;

            return socket;
        }

        protected abstract Socket Connect(EndPoint remoteEP, Socket viaSocket);

        #endregion

        #region public

        public bool IsBypassed(EndPoint ep)
        {
            foreach (NetProxyBypassItem bypassItem in _bypassList)
            {
                if (bypassItem.IsMatching(ep))
                    return true;
            }

            return false;
        }

        public abstract bool IsProxyAvailable();

        public abstract void CheckProxyAccess();

        public abstract bool IsUdpAvailable();

        public Socket Connect(string address, int port, int timeout = 10000)
        {
            return Connect(EndPointExtension.GetEndPoint(address, port), timeout);
        }

        public Socket Connect(EndPoint remoteEP, int timeout = 10000)
        {
            if (IsBypassed(remoteEP))
                return GetTcpConnection(remoteEP, timeout);

            if (_viaProxy == null)
                return Connect(remoteEP, GetTcpConnection(_proxyEP, timeout));
            else
                return Connect(remoteEP, _viaProxy.Connect(_proxyEP, timeout));
        }

        public TunnelProxy CreateTunnelProxy(string address, int port, int timeout = 10000, bool enableSsl = false, bool ignoreCertificateErrors = false)
        {
            return CreateTunnelProxy(EndPointExtension.GetEndPoint(address, port), timeout, enableSsl, ignoreCertificateErrors);
        }

        public TunnelProxy CreateTunnelProxy(EndPoint remoteEP, int timeout = 10000, bool enableSsl = false, bool ignoreCertificateErrors = false)
        {
            return new TunnelProxy(Connect(remoteEP, timeout), remoteEP, enableSsl, ignoreCertificateErrors);
        }

        public int UdpReceiveFrom(EndPoint remoteEP, byte[] request, byte[] response, int timeout = 10000)
        {
            return UdpReceiveFrom(remoteEP, request, 0, request.Length, response, 0, timeout);
        }

        public abstract int UdpReceiveFrom(EndPoint remoteEP, byte[] request, int requestOffset, int requestSize, byte[] response, int responseOffset, int timeout = 10000);

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
