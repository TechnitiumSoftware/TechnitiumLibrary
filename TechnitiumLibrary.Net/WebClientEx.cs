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
using System.Collections.Generic;
using System.IO;
using System.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net
{
    public enum WebClientExNetworkType
    {
        Default = 0,
        IPv4Only = 1,
        IPv6Only = 2
    }

    public class WebClientEx : WebClient
    {
        #region variables

        CookieContainer _cookie;
        DateTime _ifModifiedSince;
        string _userAgent;
        bool _keepAlive = true;
        Dictionary<string, string> _headers = new Dictionary<string, string>();
        int _timeout = 0;
        int _maximumAutomaticRedirections = 10;

        NetProxy _proxy;
        WebClientExNetworkType _networkType = WebClientExNetworkType.Default;

        SocksConnectRequestHandler _proxyRequestHandler;
        Stream _openResponseStream;

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

        #endregion

        #region IDisposable

        protected override void Dispose(bool disposing)
        {
            try
            {
                if (disposing)
                {
                    if (_proxyRequestHandler != null)
                        _proxyRequestHandler.Dispose();

                    if (_openResponseStream != null)
                        _openResponseStream.Dispose();
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

        public Stream OpenWriteEx(string address, string method = "POST")
        {
            return OpenWriteEx(new Uri(address), method);
        }

        public Stream OpenWriteEx(Uri address, string method = "POST")
        {
            WebRequest request = GetWebRequest(address);
            request.Method = method;

            _openResponseStream = null; //clear previous stream if any

            return new WebClientWriteStream(this, request);
        }

        public Stream GetResponseStream()
        {
            if (_openResponseStream == null)
                throw new WebException("No response stream available. Call OpenWriteEx() and close write stream to create response stream .");

            Stream s = _openResponseStream;
            _openResponseStream = null; //clear stream handle
            return s;
        }

        #endregion

        #region overrides

        protected override WebRequest GetWebRequest(Uri address)
        {
            HttpWebRequest request = null;

            if (_proxy == null)
            {
                switch (_networkType)
                {
                    case WebClientExNetworkType.IPv4Only:
                        if (IPAddress.TryParse(address.Host, out IPAddress ipv4))
                        {
                            if (ipv4.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                                throw new WebException("WebClientEx current network type does not allow url address family: " + ipv4.AddressFamily.ToString());

                            request = base.GetWebRequest(address) as HttpWebRequest;
                        }
                        else
                        {
                            try
                            {
                                DnsClient dns = new DnsClient();
                                IPAddress[] ipAddresses = dns.ResolveIP(address.Host);

                                if (ipAddresses.Length == 0)
                                    throw new WebException("WebClientEx could not resolve IPv4 address for host: " + address.Host);

                                foreach (IPAddress ipAddress in ipAddresses)
                                {
                                    if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                                    {
                                        Uri newAddress = new Uri(address.Scheme + "://" + ipAddress.ToString() + ":" + address.Port + address.PathAndQuery);
                                        request = base.GetWebRequest(newAddress) as HttpWebRequest;
                                        request.Host = address.Host;
                                        break;
                                    }
                                }
                            }
                            catch (DnsClientException ex)
                            {
                                throw new WebException("WebClientEx could not resolve IPv4 address for host: " + address.Host, ex);
                            }

                            if (request == null)
                                throw new WebException("WebClientEx could not resolve IPv4 address for host: " + address.Host);
                        }
                        break;

                    case WebClientExNetworkType.IPv6Only:
                        if (IPAddress.TryParse(address.Host, out IPAddress ipv6))
                        {
                            if (ipv6.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                                throw new WebException("WebClientEx current network type does not allow url address family: " + ipv6.AddressFamily.ToString());

                            request = base.GetWebRequest(address) as HttpWebRequest;
                        }
                        else
                        {
                            try
                            {
                                DnsClient dns = new DnsClient(true);
                                IPAddress[] ipAddresses = dns.ResolveIP(address.Host, true);

                                if (ipAddresses.Length == 0)
                                    throw new WebException("WebClientEx could not resolve IPv6 address for host: " + address.Host);

                                foreach (IPAddress ipAddress in ipAddresses)
                                {
                                    if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                                    {
                                        Uri newAddress = new Uri(address.Scheme + "://[" + ipAddress.ToString() + "]:" + address.Port + address.PathAndQuery);
                                        request = base.GetWebRequest(newAddress) as HttpWebRequest;
                                        request.Host = address.Host;
                                        break;
                                    }
                                }
                            }
                            catch (DnsClientException ex)
                            {
                                throw new WebException("WebClientEx could not resolve IPv6 address for host: " + address.Host, ex);
                            }

                            if (request == null)
                                throw new WebException("WebClientEx could not resolve IPv6 address for host: " + address.Host);
                        }
                        break;

                    default:
                        request = base.GetWebRequest(address) as HttpWebRequest;
                        break;
                }
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

        public WebClientExNetworkType NetworkType
        {
            get { return _networkType; }
            set { _networkType = value; }
        }

        #endregion

        class WebClientWriteStream : Stream
        {
            #region variables

            readonly WebClientEx _webClient;
            readonly WebRequest _request;
            readonly Stream _requestStream;

            #endregion

            #region constructor

            public WebClientWriteStream(WebClientEx webClient, WebRequest request)
            {
                _webClient = webClient;
                _request = request;
                _requestStream = request.GetRequestStream();
            }

            #endregion

            #region public

            protected override void Dispose(bool disposing)
            {
                try
                {
                    if (disposing)
                    {
                        _requestStream.Close();
                        WebResponse response = _webClient.GetWebResponse(_request);
                        _webClient._openResponseStream = response.GetResponseStream();
                    }
                }
                finally
                {
                    base.Dispose(disposing);
                }
            }

            #endregion

            #region stream support

            public override bool CanRead
            { get { return false; } }

            public override bool CanSeek
            { get { return false; } }

            public override bool CanWrite
            { get { return true; } }

            public override long Length
            { get { throw new NotImplementedException(); } }

            public override long Position
            {
                get { throw new NotImplementedException(); }
                set { throw new NotImplementedException(); }
            }

            public override void Flush()
            {
                _requestStream.Flush();
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                throw new NotImplementedException();
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotImplementedException();
            }

            public override void SetLength(long value)
            {
                throw new NotImplementedException();
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                _requestStream.Write(buffer, offset, count);
            }

            #endregion
        }
    }
}