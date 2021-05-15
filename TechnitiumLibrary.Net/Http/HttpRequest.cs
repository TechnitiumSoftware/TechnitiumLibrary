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
using System.Collections.Specialized;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.Http
{
    public class HttpRequest
    {
        #region variables

        const int BUFFER_SIZE = 8 * 1024;

        string _httpMethod;
        string _requestPath;
        string _requestPathAndQuery;
        string _protocol;
        readonly NameValueCollection _queryString = new NameValueCollection();
        readonly WebHeaderCollection _headers = new WebHeaderCollection();

        Stream _inputStream;

        #endregion

        #region constructor

        private HttpRequest()
        { }

        #endregion

        #region static

        public static async Task<HttpRequest> ReadRequestAsync(Stream stream)
        {
            HttpRequest httpRequest = new HttpRequest();

            //parse http request headers
            using (MemoryStream headerBuffer = new MemoryStream())
            {
                //read http request header into memory stream
                byte[] buffer = new byte[BUFFER_SIZE];
                int offset = 0;
                int length = 0;
                int crlfCount = 0;
                bool firstRead = true;

                while (crlfCount != 4)
                {
                    length = await stream.ReadAsync(buffer);
                    if (length < 1)
                    {
                        if (firstRead)
                            return null; //connection closed gracefully by client

                        throw new EndOfStreamException();
                    }

                    firstRead = false;

                    for (offset = 0; offset < length; offset++)
                    {
                        switch (buffer[offset])
                        {
                            case 13: //CR
                            case 10: //LF
                                crlfCount++;
                                break;

                            default:
                                crlfCount = 0;
                                break;
                        }

                        headerBuffer.WriteByte(buffer[offset]);

                        if (crlfCount == 4)
                        {
                            offset++;
                            break; //http request completed
                        }
                    }
                }

                //parse http header data from memory stream
                headerBuffer.Position = 0;
                StreamReader sR = new StreamReader(headerBuffer);

                string[] requestParts = sR.ReadLine().Split(new char[] { ' ' }, 3);

                if (requestParts.Length != 3)
                    throw new InvalidDataException("Invalid HTTP request.");

                httpRequest._httpMethod = requestParts[0];
                httpRequest._requestPathAndQuery = requestParts[1];
                httpRequest._protocol = requestParts[2];

                string[] requestPathAndQueryParts = httpRequest._requestPathAndQuery.Split(new char[] { '?' }, 2);

                httpRequest._requestPath = requestPathAndQueryParts[0];

                string queryString = null;
                if (requestPathAndQueryParts.Length > 1)
                    queryString = requestPathAndQueryParts[1];

                if (!string.IsNullOrEmpty(queryString))
                {
                    foreach (string item in queryString.Split(new char[] { '&' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        string[] itemParts = item.Split(new char[] { '=' }, 2);

                        string name = itemParts[0];
                        string value = null;

                        if (itemParts.Length > 1)
                            value = itemParts[1];

                        httpRequest._queryString.Add(name, value);
                    }
                }

                while (true)
                {
                    string line = sR.ReadLine();
                    if (string.IsNullOrEmpty(line))
                        break;

                    string[] parts = line.Split(new char[] { ':' }, 2);
                    if (parts.Length != 2)
                        throw new InvalidDataException("Invalid HTTP request.");

                    httpRequest._headers.Add(parts[0], parts[1]);
                }

                string strContentLength = httpRequest._headers[HttpRequestHeader.ContentLength];
                if (!string.IsNullOrEmpty(strContentLength))
                {
                    httpRequest._inputStream = new HttpContentStream(stream, buffer, offset, length, int.Parse(strContentLength));
                    return httpRequest;
                }

                string strTransferEncoding = httpRequest._headers[HttpRequestHeader.TransferEncoding];
                if (!string.IsNullOrEmpty(strTransferEncoding))
                {
                    if (!strTransferEncoding.Equals("chunked", StringComparison.OrdinalIgnoreCase))
                        throw new HttpRequestException("Transfer encoding is not supported: " + strTransferEncoding);

                    httpRequest._inputStream = new HttpChunkedStream(new HttpContentStream(stream, buffer, offset, length));
                    return httpRequest;
                }
            }

            return httpRequest;
        }

        #endregion

        #region properties

        public string HttpMethod
        { get { return _httpMethod; } }

        public string RequestPath
        { get { return _requestPath; } }

        public string RequestPathAndQuery
        { get { return _requestPathAndQuery; } }

        public string Protocol
        { get { return _protocol; } }

        public NameValueCollection QueryString
        { get { return _queryString; } }

        public WebHeaderCollection Headers
        { get { return _headers; } }

        public Stream InputStream
        { get { return _inputStream; } }

        #endregion
    }
}
