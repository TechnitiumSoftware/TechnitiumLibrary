/*
Technitium Library
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.Http
{
    public class HttpResponse
    {
        #region variables

        const int BUFFER_SIZE = 8 * 1024;

        private static readonly char[] spaceSeparator = new char[] { ' ' };
        private static readonly char[] colonSeparator = new char[] { ':' };

        string _protocol;
        int _statusCode;
        string _statusMessage;

        readonly WebHeaderCollection _headers = new WebHeaderCollection();

        Stream _outputStream;

        #endregion

        #region constructor

        private HttpResponse()
        { }

        #endregion

        #region static

        public static async Task<HttpResponse> ReadResponseAsync(Stream stream, CancellationToken cancellationToken = default)
        {
            HttpResponse httpResponse = new HttpResponse();

            //parse http request headers
            using (MemoryStream headerBuffer = new MemoryStream())
            {
                //read http request header into memory stream
                byte[] buffer = new byte[BUFFER_SIZE];
                int offset = 0;
                int length = 0;
                int crlfCount = 0;

                while (crlfCount != 4)
                {
                    length = await stream.ReadAsync(buffer, cancellationToken);
                    if (length < 1)
                        throw new EndOfStreamException();

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

                string[] requestParts = sR.ReadLine().Split(spaceSeparator, 3);

                if (requestParts.Length != 3)
                    throw new InvalidDataException("Invalid HTTP request.");

                httpResponse._protocol = requestParts[0];
                httpResponse._statusCode = int.Parse(requestParts[1]);
                httpResponse._statusMessage = requestParts[2];

                while (true)
                {
                    string line = sR.ReadLine();
                    if (string.IsNullOrEmpty(line))
                        break;

                    string[] parts = line.Split(colonSeparator, 2);
                    if (parts.Length != 2)
                        throw new InvalidDataException("Invalid HTTP response.");

                    httpResponse._headers.Add(parts[0], parts[1]);
                }

                string strContentLength = httpResponse._headers[HttpRequestHeader.ContentLength];
                if (!string.IsNullOrEmpty(strContentLength))
                {
                    httpResponse._outputStream = new HttpContentStream(stream, buffer, offset, length, int.Parse(strContentLength));
                    return httpResponse;
                }

                string strTransferEncoding = httpResponse._headers[HttpRequestHeader.TransferEncoding];
                if (!string.IsNullOrEmpty(strTransferEncoding))
                {
                    if (!strTransferEncoding.Equals("chunked", StringComparison.OrdinalIgnoreCase))
                        throw new HttpRequestException("Transfer encoding is not supported: " + strTransferEncoding);

                    httpResponse._outputStream = new HttpChunkedStream(new HttpContentStream(stream, buffer, offset, length));
                    return httpResponse;
                }
            }

            return httpResponse;
        }

        #endregion

        #region properties

        public string Protocol
        { get { return _protocol; } }

        public int StatusCode
        { get { return _statusCode; } }

        public string StatusMessage
        { get { return _statusMessage; } }

        public WebHeaderCollection Headers
        { get { return _headers; } }

        public Stream OutputStream
        { get { return _outputStream; } }

        #endregion
    }
}
