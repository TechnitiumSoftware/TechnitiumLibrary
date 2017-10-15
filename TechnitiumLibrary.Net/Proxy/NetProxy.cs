/*
Technitium Library
Copyright (C) 2017  Shreyas Zare (shreyas@technitium.com)

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
    public enum NetProxyType
    {
        None = 0,
        Http = 1,
        Socks5 = 2
    }

    public class NetProxy
    {
        #region variables

        NetProxyType _type;

        WebProxyEx _httpProxy;
        SocksClient _socksProxy;

        #endregion

        #region constructor

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

        #endregion

        #region public

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

        public Socket Connect(IPEndPoint remoteEP)
        {
            switch (_type)
            {
                case NetProxyType.Http:
                    return _httpProxy.Connect(remoteEP);

                case NetProxyType.Socks5:
                    using (SocksConnectRequestHandler requestHandler = _socksProxy.Connect(remoteEP))
                    {
                        return requestHandler.GetSocket();
                    }

                default:
                    throw new NotSupportedException("Proxy type not supported.");
            }
        }

        #endregion

        #region properties

        public NetProxyType Type
        { get { return _type; } }

        public WebProxyEx HttpProxy
        { get { return _httpProxy; } }

        public SocksClient SocksProxy
        { get { return _socksProxy; } }

        #endregion
    }
}
