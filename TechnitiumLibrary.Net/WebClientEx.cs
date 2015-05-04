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

namespace TechnitiumLibrary.Net
{
    public class WebClientEx : System.Net.WebClient
    {
        #region variables

        CookieContainer _cookie;
        Dictionary<string, string> _headers = new Dictionary<string, string>();
        int _timeout = 0;

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
            WebRequest request = base.GetWebRequest(address);

            if (_timeout > 0)
                request.Timeout = _timeout;

            if (request is HttpWebRequest)
            {
                HttpWebRequest httpRequest = request as HttpWebRequest;

                httpRequest.CookieContainer = _cookie;

                foreach (KeyValuePair<string, string> header in _headers)
                {
                    switch (header.Key.ToLower())
                    {
                        case "accept":
                            httpRequest.Accept = header.Value;
                            break;

                        case "connection":
                            httpRequest.KeepAlive = (header.Value.ToLower() == "keep-alive");
                            break;

                        case "content-type":
                            httpRequest.ContentType = header.Value;
                            break;

                        case "user-agent":
                            httpRequest.UserAgent = header.Value;
                            break;

                        default:
                            httpRequest.Headers.Add(header.Key, header.Value);
                            break;
                    }
                }


            }

            return request;
        }

        #endregion

        #region properties

        public CookieContainer Cookie
        {
            get { return _cookie; }
            set { _cookie = value; }
        }

        public int Timeout
        {
            get { return _timeout; }
            set { _timeout = value; }
        }

        #endregion
    }
}