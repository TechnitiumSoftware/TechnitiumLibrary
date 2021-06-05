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
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.Http
{
    class HttpContentStream : Stream
    {
        #region variables

        readonly Stream _baseStream;

        readonly byte[] _buffer;
        int _offset;
        int _length;

        readonly int _contentLength;
        int _totalBytesRead;

        #endregion

        #region constructor

        public HttpContentStream(Stream baseStream, byte[] buffer, int offset, int length, int contentLength = -1)
        {
            _baseStream = baseStream;

            _buffer = buffer;
            _offset = offset;
            _length = length;

            _contentLength = contentLength;
        }

        #endregion

        #region private

        private int ReadBuffer(byte[] buffer, int offset, int count)
        {
            if (_offset < _length)
            {
                int bytesAvailable = _length - _offset;
                if (count > bytesAvailable)
                    count = bytesAvailable;

                Buffer.BlockCopy(_buffer, _offset, buffer, offset, count);
                _offset += count;
                _totalBytesRead += count;
                return count;
            }

            return 0;
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
        { get { return _contentLength; } }

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
                int bytesRead = ReadBuffer(buffer, offset, count);
                if (bytesRead > 0)
                    return bytesRead;

                //fill buffer
                int bytesRemaining;

                if (_contentLength > -1)
                {
                    bytesRemaining = _contentLength - _totalBytesRead;
                    if (bytesRemaining > _buffer.Length)
                        bytesRemaining = _buffer.Length;

                    if (bytesRemaining < 1)
                        return 0;
                }
                else
                {
                    bytesRemaining = _buffer.Length;
                }

                bytesRead = _baseStream.Read(_buffer, 0, bytesRemaining);
                if (bytesRead < 1)
                    return bytesRead;

                _offset = 0;
                _length = bytesRead;
            }
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            while (true)
            {
                if (cancellationToken.IsCancellationRequested)
                    return await Task.FromCanceled<int>(cancellationToken);

                //read from buffer
                int bytesRead = ReadBuffer(buffer, offset, count);
                if (bytesRead > 0)
                    return bytesRead;

                //fill buffer
                int bytesRemaining;

                if (_contentLength > -1)
                {
                    bytesRemaining = _contentLength - _totalBytesRead;
                    if (bytesRemaining > _buffer.Length)
                        bytesRemaining = _buffer.Length;

                    if (bytesRemaining < 1)
                        return 0;
                }
                else
                {
                    bytesRemaining = _buffer.Length;
                }

                bytesRead = await _baseStream.ReadAsync(_buffer, 0, bytesRemaining, cancellationToken);
                if (bytesRead < 1)
                    return bytesRead;

                _offset = 0;
                _length = bytesRead;
            }
        }

        #endregion
    }
}
