/*
Technitium Library
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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

        readonly MemoryStream _buffer = new MemoryStream(1024);

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
            if (count < 1)
                return 0;

            while (true)
            {
                //read from buffer
                int bytesRead = _buffer.Read(buffer, offset, count);
                if (bytesRead > 0)
                    return bytesRead;

                if ((_maxContentLength > -1) && (_baseStream.TotalBytesRead > _maxContentLength))
                    throw new HttpRequestException("Response content size is greater than max content length: " + _baseStream.TotalBytesRead);

                int chunkLength = ReadChunkLength();

                _buffer.SetLength(0);

                if (chunkLength > 0)
                {
                    _baseStream.CopyTo(_buffer, BUFFER_SIZE, chunkLength);
                    _buffer.Position = 0;
                    ReadChunkDelimiter();
                }
                else
                {
                    ReadTrailers();
                    _baseStream.ReturnUnused();
                    return 0;
                }
            }
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (count < 1)
                return 0;

            while (true)
            {
                int bytesRead = _buffer.Read(buffer, offset, count);
                if (bytesRead > 0)
                    return bytesRead;

                if ((_maxContentLength > -1) && (_baseStream.TotalBytesRead > _maxContentLength))
                    throw new HttpRequestException("Response content size is greater than max content length: " + _baseStream.TotalBytesRead);

                int chunkLength = await ReadChunkLengthAsync(cancellationToken);

                _buffer.SetLength(0);

                if (chunkLength > 0)
                {
                    await _baseStream.CopyToAsync(_buffer, BUFFER_SIZE, chunkLength, cancellationToken);
                    _buffer.Position = 0;
                    await ReadChunkDelimiterAsync(cancellationToken);
                }
                else
                {
                    await ReadTrailersAsync(cancellationToken);
                    _baseStream.ReturnUnused();
                    return 0;
                }
            }
        }

        void ReadChunkDelimiter()
        {
            byte[] crlf = new byte[2];
            int read = 0;

            while (read < crlf.Length)
            {
                int bytesRead = _baseStream.Read(crlf, read, crlf.Length - read);
                if (bytesRead < 1)
                    throw new EndOfStreamException();

                read += bytesRead;
            }

            if ((crlf[0] != (byte)'\r') || (crlf[1] != (byte)'\n'))
                throw new HttpRequestException("Chunk is not terminated by CRLF.");
        }

        async Task ReadChunkDelimiterAsync(CancellationToken cancellationToken)
        {
            byte[] crlf = new byte[2];
            int read = 0;

            while (read < crlf.Length)
            {
                int bytesRead = await _baseStream.ReadAsync(crlf, read, crlf.Length - read, cancellationToken);
                if (bytesRead < 1)
                    throw new EndOfStreamException();

                read += bytesRead;
            }

            if ((crlf[0] != (byte)'\r') || (crlf[1] != (byte)'\n'))
                throw new HttpRequestException("Chunk is not terminated by CRLF.");
        }

        void ReadTrailers()
        {
            byte[] one = new byte[1];

            while (true)
            {
                bool lineEmpty = true;

                while (true)
                {
                    if (_baseStream.Read(one, 0, 1) < 1)
                        throw new EndOfStreamException();

                    if (one[0] == (byte)'\n')
                        break;

                    if (one[0] != (byte)'\r')
                        lineEmpty = false;
                }

                if (lineEmpty)
                    return;
            }
        }

        async Task ReadTrailersAsync(CancellationToken cancellationToken)
        {
            byte[] one = new byte[1];

            while (true)
            {
                bool lineEmpty = true;

                while (true)
                {
                    if (await _baseStream.ReadAsync(one, 0, 1, cancellationToken) < 1)
                        throw new EndOfStreamException();

                    if (one[0] == (byte)'\n')
                        break;

                    if (one[0] != (byte)'\r')
                        lineEmpty = false;
                }

                if (lineEmpty)
                    return;
            }
        }

        int ReadChunkLength()
        {
            byte[] one = new byte[1];
            return ParseChunkLength(delegate ()
            {
                if (_baseStream.Read(one, 0, 1) < 1)
                    throw new EndOfStreamException();

                return one[0];
            });
        }

        async Task<int> ReadChunkLengthAsync(CancellationToken cancellationToken)
        {
            byte[] hex = new byte[16];
            int hexLength = 0;
            bool extension = false;
            byte[] one = new byte[1];

            while (true)
            {
                if (await _baseStream.ReadAsync(one, 0, 1, cancellationToken) < 1)
                    throw new EndOfStreamException();

                if (AcceptChunkSizeByte(one[0], hex, ref hexLength, ref extension))
                    break;
            }

            return FinishChunkLength(hex, hexLength);
        }

        int ParseChunkLength(Func<byte> readByte)
        {
            byte[] hex = new byte[16];
            int hexLength = 0;
            bool extension = false;

            while (true)
            {
                if (AcceptChunkSizeByte(readByte(), hex, ref hexLength, ref extension))
                    break;
            }

            return FinishChunkLength(hex, hexLength);
        }

        static bool AcceptChunkSizeByte(byte value, byte[] hex, ref int hexLength, ref bool extension)
        {
            switch (value)
            {
                case 10: //LF
                    return true;

                case 13: //CR
                    return false;

                case (byte)';':
                case (byte)' ':
                case (byte)'\t':
                    extension = true;
                    return false;

                default:
                    if (extension)
                        return false;

                    if (hexLength == hex.Length)
                        throw new HttpRequestException("Chunk size is too long.");

                    if (!IsHex(value))
                        throw new HttpRequestException("Chunk size is not hexadecimal.");

                    hex[hexLength++] = value;
                    return false;
            }
        }

        static int FinishChunkLength(byte[] hex, int hexLength)
        {
            if (hexLength == 0)
                throw new HttpRequestException("Chunk size is missing.");

            if (!long.TryParse(Encoding.ASCII.GetString(hex, 0, hexLength), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long chunkLength) || (chunkLength < 0) || (chunkLength > int.MaxValue))
                throw new HttpRequestException("Chunk size is invalid.");

            return (int)chunkLength;
        }

        static bool IsHex(byte value)
        {
            return ((value >= (byte)'0') && (value <= (byte)'9')) || ((value >= (byte)'a') && (value <= (byte)'f')) || ((value >= (byte)'A') && (value <= (byte)'F'));
        }

        #endregion
    }
}
