using System;

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
                    return WebUtilities.IsWebAccessible(null, this, false, 5000);

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
                    WebUtilities.IsWebAccessible(null, this, true, 5000);
                    break;

                case NetProxyType.Socks5:
                    _socksProxy.CheckProxyAccess();
                    break;

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
