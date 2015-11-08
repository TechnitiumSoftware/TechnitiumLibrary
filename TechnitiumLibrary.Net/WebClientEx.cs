/*
Technitium Library
Copyright (C) 2015  Shreyas Zare (shreyas@technitium.com)

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
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net
{
    public class WebClientEx : WebClient
    {
        #region variables

        NetProxy _proxy;

        CookieContainer _cookie;
        DateTime _ifModifiedSince;
        string _userAgent;
        bool _keepAlive = true;
        Dictionary<string, string> _headers = new Dictionary<string, string>();
        int _timeout = 0;
        int _maximumAutomaticRedirections = 10;

        SocksConnectRequestHandler _proxyRequestHandler;

        #endregion

        #region constructor

        public WebClientEx()
        {
            _cookie = new CookieContainer();
        }

        public WebClientEx(CookieContainer cookie)
        {
            _cookie = cookie;
        }

        public WebClientEx(int timeout)
        {
            _cookie = new CookieContainer();
            _timeout = timeout;
        }

        #endregion

        #region IDisposable

        protected override void Dispose(bool disposing)
        {
            try
            {
                if (_proxyRequestHandler != null)
                {
                    _proxyRequestHandler.Dispose();
                    _proxyRequestHandler = null;
                }
            }
            finally
            {
                base.Dispose(disposing);
            }
        }

        #endregion

        #region public

        public void ClearCookies()
        {
            _cookie = new CookieContainer();
        }

        public void AddHeader(string name, string value)
        {
            _headers.Add(name, value);
        }

        public bool RemoveHeader(string name)
        {
            return _headers.Remove(name);
        }

        public void ClearHeaders()
        {
            _headers.Clear();
        }

        #endregion

        #region overrides

        protected override WebRequest GetWebRequest(Uri address)
        {
            HttpWebRequest request;

            if (_proxy == null)
            {
                request = base.GetWebRequest(address) as HttpWebRequest;
            }
            else
            {
                switch (_proxy.Type)
                {
                    case NetProxyType.Http:
                        request = base.GetWebRequest(address) as HttpWebRequest;
                        request.Proxy = _proxy.HttpProxy;
                        break;

                    case NetProxyType.Socks5:
                        _proxyRequestHandler = _proxy.SocksProxy.Connect(address.Host, address.Port);

                        if (address.Scheme == "https")
                        {
                            IWebProxy httpProxy = _proxyRequestHandler.CreateLocalHttpProxyConnectTunnel();

                            request = base.GetWebRequest(address) as HttpWebRequest;
                            request.Proxy = httpProxy;
                        }
                        else
                        {
                            IPEndPoint localTunnelEP = _proxyRequestHandler.CreateLocalTunnel();
                            Uri proxyUri = new Uri("http://" + localTunnelEP.Address.ToString() + ":" + localTunnelEP.Port + address.PathAndQuery);

                            request = base.GetWebRequest(proxyUri) as HttpWebRequest;
                            request.Host = address.Host;
                        }
                        break;

                    default:
                        throw new NotSupportedException("Proxy type not supported.");
                }
            }

            if (_timeout > 0)
                request.Timeout = _timeout;

            request.CookieContainer = _cookie;

            if (_ifModifiedSince > (new DateTime()))
                request.IfModifiedSince = _ifModifiedSince;

            if (_userAgent != null)
                request.UserAgent = _userAgent;

            request.KeepAlive = _keepAlive;

            request.AllowAutoRedirect = false;

            foreach (KeyValuePair<string, string> header in _headers)
            {
                switch (header.Key.ToLower())
                {
                    case "accept":
                        request.Accept = header.Value;
                        break;

                    case "connection":
                        request.KeepAlive = (header.Value.ToLower() == "keep-alive");
                        break;

                    case "content-type":
                        request.ContentType = header.Value;
                        break;

                    case "user-agent":
                        request.UserAgent = header.Value;
                        break;

                    default:
                        request.Headers.Add(header.Key, header.Value);
                        break;
                }
            }

            return request;
        }

        protected override WebResponse GetWebResponse(WebRequest request)
        {
            HttpWebResponse response = null;
            int redirectCount = -1;

            while (redirectCount < _maximumAutomaticRedirections)
            {
                try
                {
                    response = request.GetResponse() as HttpWebResponse;
                }
                finally
                {
                    if (_proxyRequestHandler != null)
                    {
                        _proxyRequestHandler.Dispose();
                        _proxyRequestHandler = null;
                    }
                }

                switch (response.StatusCode)
                {
                    case HttpStatusCode.MovedPermanently:
                    case HttpStatusCode.Found:
                    case HttpStatusCode.SeeOther:
                        request = GetWebRequest(new Uri(response.Headers["location"]));
                        break;

                    case HttpStatusCode.RedirectKeepVerb:
                        string method = request.Method;
                        request = GetWebRequest(new Uri(response.Headers["location"]));
                        request.Method = method;
                        break;

                    default:
                        return response;
                }

                redirectCount++;
            }

            throw new WebException("Too many automatic redirections were attempted.", null, WebExceptionStatus.ProtocolError, response);
        }

        protected override WebResponse GetWebResponse(WebRequest request, IAsyncResult result)
        {
            return GetWebResponse(request);
        }

        #endregion

        #region properties

        public CookieContainer Cookie
        {
            get { return _cookie; }
            set { _cookie = value; }
        }

        public DateTime IfModifiedSince
        {
            get { return _ifModifiedSince; }
            set { _ifModifiedSince = value; }
        }

        public string UserAgent
        {
            get { return _userAgent; }
            set { _userAgent = value; }
        }

        public bool KeepAlive
        {
            get { return _keepAlive; }
            set { _keepAlive = value; }
        }

        public int Timeout
        {
            get { return _timeout; }
            set { _timeout = value; }
        }

        public int MaximumAutomaticRedirections
        {
            get { return _maximumAutomaticRedirections; }
            set { _maximumAutomaticRedirections = value; }
        }

        public new NetProxy Proxy
        {
            get { return _proxy; }
            set { _proxy = value; }
        }

        #endregion
    }
}