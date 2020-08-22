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
using System.IO;
using System.IO.Compression;
using System.Net;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;

namespace TechnitiumLibrary.Net
{
    public enum WebClientExNetworkType
    {
        Default = 0,
        IPv4Only = 1,
        IPv6Only = 2
    }

    [Obsolete]
    public class WebClientEx : WebClient
    {
        #region variables

        CookieContainer _cookie;
        DateTime _ifModifiedSince;
        string _userAgent;
        bool _keepAlive = true;
        readonly Dictionary<string, string> _headers = new Dictionary<string, string>();
        int _timeout = 90000;
        bool _enableAutomaticDecompression = true;

        WebClientExNetworkType _networkType = WebClientExNetworkType.Default;

        WebResponse _response;

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

        public WriteStream OpenWriteEx(string address, string method = "POST", bool gzip = false)
        {
            return OpenWriteEx(new Uri(address), method, gzip);
        }

        public WriteStream OpenWriteEx(Uri address, string method = "POST", bool gzip = false)
        {
            WebRequest request = GetWebRequest(address);
            request.Method = method;

            return new WriteStream(this, request, gzip);
        }

        #endregion

        #region overrides

        protected override WebRequest GetWebRequest(Uri address)
        {
            HttpWebRequest request = null;

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
                            IReadOnlyList<IPAddress> ipAddresses = dns.ResolveIPAsync(address.Host).Sync();

                            if (ipAddresses.Count == 0)
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
                            IReadOnlyList<IPAddress> ipAddresses = dns.ResolveIPAsync(address.Host, true).Sync();

                            if (ipAddresses.Count == 0)
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

            if (_timeout > 0)
                request.Timeout = _timeout;

            request.CookieContainer = _cookie;

            if (_ifModifiedSince > DateTime.MinValue)
                request.IfModifiedSince = _ifModifiedSince;

            if (_userAgent != null)
                request.UserAgent = _userAgent;

            request.KeepAlive = _keepAlive;

            if (_enableAutomaticDecompression)
                request.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;

            foreach (KeyValuePair<string, string> header in _headers)
            {
                switch (header.Key.ToLower())
                {
                    case "accept":
                        request.Accept = header.Value;
                        break;

                    case "connection":
                        request.KeepAlive = header.Value.Equals("keep-alive", StringComparison.OrdinalIgnoreCase);
                        break;

                    case "content-type":
                        request.ContentType = header.Value;
                        break;

                    case "user-agent":
                        request.UserAgent = header.Value;
                        break;

                    case "host":
                        request.Host = header.Value;
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
            _response = base.GetWebResponse(request);
            return _response;

        }

        protected override WebResponse GetWebResponse(WebRequest request, IAsyncResult result)
        {
            _response = base.GetWebResponse(request, result);
            return _response;
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

        public WebResponse Response
        { get { return _response; } }

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

        public bool EnableAutomaticDecompression
        {
            get { return _enableAutomaticDecompression; }
            set { _enableAutomaticDecompression = value; }
        }

        public WebClientExNetworkType NetworkType
        {
            get { return _networkType; }
            set { _networkType = value; }
        }

        #endregion

        public class WriteStream : Stream
        {
            #region variables

            readonly WebClientEx _webClient;
            readonly WebRequest _request;
            readonly Stream _requestStream;

            #endregion

            #region constructor

            public WriteStream(WebClientEx webClient, WebRequest request, bool gzip)
            {
                _webClient = webClient;
                _request = request;

                if (gzip)
                {
                    _request.Headers.Add("Content-Encoding", "gzip");
                    _requestStream = new GZipStream(request.GetRequestStream(), CompressionMode.Compress);
                }
                else
                {
                    _requestStream = request.GetRequestStream();
                }
            }

            #endregion

            #region IDisposable

            private bool _disposed = false;

            protected override void Dispose(bool disposing)
            {
                try
                {
                    if (_disposed)
                        return;

                    if (disposing)
                    {
                        if (_requestStream != null)
                            _requestStream.Dispose();
                    }

                    _disposed = true;
                }
                finally
                {
                    base.Dispose(disposing);
                }
            }

            #endregion

            #region public

            public Stream GetResponseStream()
            {
                return _webClient.GetWebResponse(_request).GetResponseStream();
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
            { get { throw new NotSupportedException(); } }

            public override long Position
            {
                get { throw new NotSupportedException(); }
                set { throw new NotSupportedException(); }
            }

            public override void Flush()
            {
                _requestStream.Flush();
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                throw new NotSupportedException();
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotSupportedException();
            }

            public override void SetLength(long value)
            {
                throw new NotSupportedException();
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                _requestStream.Write(buffer, offset, count);
            }

            #endregion
        }
    }
}