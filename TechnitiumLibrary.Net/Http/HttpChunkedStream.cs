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
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Http
{
    class HttpChunkedStream : Stream
    {
        #region variables

        const int BUFFER_SIZE = 8 * 1024;

        readonly HttpContentStream _baseStream;
        readonly int _maxContentLength;

        readonly MemoryStream _buffer = new MemoryStream();

        #endregion

        #region constructor

        public HttpChunkedStream(HttpContentStream baseStream, int maxContentLength = -1)
        {
            _baseStream = baseStream;
            _maxContentLength = maxContentLength;
        }

        #endregion

        #region stream support

        public override bool CanRead
        { get { return _baseStream.CanRead; } }

        public override bool CanSeek
        { get { return false; } }

        public override bool CanWrite
        { get { return false; } }

        public override long Length
        { get { throw new NotSupportedException(); } }

        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        public override void Flush()
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
            throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            while (true)
            {
                //read from buffer
                int bytesRead = _buffer.Read(buffer, 0, count);
                if (bytesRead > 0)
                    return bytesRead;

                if ((_maxContentLength > -1) && (_baseStream.TotalBytesRead > _maxContentLength))
                    throw new HttpRequestException("Response content size is greater than max content length: " + _baseStream.TotalBytesRead);

                //fill buffer
                byte[] byteBuffer = new byte[1];
                byte[] strHexLength = new byte[8];
                bool breakWhile = false;
                int strHexPosition = 0;

                while (!breakWhile)
                {
                    bytesRead = _baseStream.Read(byteBuffer, 0, 1);
                    if (bytesRead < 1)
                        throw new EndOfStreamException();

                    switch (byteBuffer[0])
                    {
                        case 13: //CR
                            break;

                        case 10: //LF
                            breakWhile = true;
                            break;

                        default:
                            strHexLength[strHexPosition++] = byteBuffer[0];
                            break;
                    }
                }

                int chunkLength = int.Parse(Encoding.ASCII.GetString(strHexLength, 0, strHexPosition), NumberStyles.HexNumber);

                _buffer.SetLength(0);

                if (chunkLength > 0)
                {
                    _baseStream.CopyTo(_buffer, BUFFER_SIZE, chunkLength);
                    _buffer.Position = 0;
                }

                _baseStream.CopyTo(Null, 2, 2); //remove trailing \r\n

                if (chunkLength == 0)
                    return 0;
            }
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            while (true)
            {
                int bytesRead = _buffer.Read(buffer, 0, count);
                if (bytesRead > 0)
                    return bytesRead;

                if ((_maxContentLength > -1) && (_baseStream.TotalBytesRead > _maxContentLength))
                    throw new HttpRequestException("Response content size is greater than max content length: " + _baseStream.TotalBytesRead);

                //fill buffer
                byte[] byteBuffer = new byte[1];
                byte[] strHexLength = new byte[8];
                bool breakWhile = false;
                int strHexPosition = 0;

                while (!breakWhile)
                {
                    bytesRead = await _baseStream.ReadAsync(byteBuffer, 0, 1, cancellationToken);
                    if (bytesRead < 1)
                        throw new EndOfStreamException();

                    switch (byteBuffer[0])
                    {
                        case 13: //CR
                            break;

                        case 10: //LF
                            breakWhile = true;
                            break;

                        default:
                            strHexLength[strHexPosition++] = byteBuffer[0];
                            break;
                    }
                }

                int chunkLength = int.Parse(Encoding.ASCII.GetString(strHexLength, 0, strHexPosition), NumberStyles.HexNumber);

                _buffer.SetLength(0);

                if (chunkLength > 0)
                {
                    await _baseStream.CopyToAsync(_buffer, BUFFER_SIZE, chunkLength, cancellationToken);
                    _buffer.Position = 0;
                }

                await _baseStream.CopyToAsync(Null, 2, 2, cancellationToken); //remove trailing \r\n

                if (chunkLength == 0)
                    return 0;
            }
        }

        #endregion
    }
}
