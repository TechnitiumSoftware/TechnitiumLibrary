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
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary.IO
{
    public class OffsetStream : Stream
    {
        #region variables

        readonly Stream _stream;
        readonly long _offset;
        long _length;
        long _position;
        readonly bool _readOnly;
        readonly bool _ownsStream;

        #endregion

        #region constructor

        public OffsetStream(Stream stream, long offset = 0, long length = 0, bool readOnly = false, bool ownsStream = false)
        {
            _stream = stream;
            _offset = offset;
            _length = length;
            _readOnly = readOnly;
            _ownsStream = ownsStream;
        }

        #endregion

        #region IDisposable

        bool _disposed = false;

        protected override void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_ownsStream & (_stream != null))
                    _stream.Dispose();
            }

            _disposed = true;

            base.Dispose(disposing);
        }

        #endregion

        #region stream support

        public override bool CanRead
        { get { return _stream.CanRead; } }

        public override bool CanSeek
        { get { return _stream.CanSeek; } }

        public override bool CanWrite
        { get { return _stream.CanWrite && !_readOnly; } }

        public override bool CanTimeout
        { get { return _stream.CanTimeout; } }

        public override long Length
        { get { return _length; } }

        public override long Position
        {
            get
            {
                return _position;
            }
            set
            {
                if (_readOnly && (value > _length))
                    throw new EndOfStreamException();

                if (!_stream.CanSeek)
                    throw new InvalidOperationException("Cannot seek stream.");

                _position = value;
                _stream.Position = _offset + _position;

                if (_position > _length)
                    _length = _position;
            }
        }

        public override void Flush()
        {
            if (_readOnly)
                throw new InvalidOperationException("OffsetStream is read only.");

            _stream.Flush();
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            if (_readOnly)
                throw new InvalidOperationException("OffsetStream is read only.");

            return _stream.FlushAsync(cancellationToken);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (count < 1)
                return 0;

            if (_position >= _length)
                return 0;

            int available = Convert.ToInt32(_length - _position);

            if (count > available)
                count = available;

            if (_stream.CanSeek)
                _stream.Position = _offset + _position;

            int bytesRead = _stream.Read(buffer, offset, count);
            _position += bytesRead;

            return bytesRead;
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (count < 1)
                return 0;

            if (_position >= _length)
                return 0;

            int available = Convert.ToInt32(_length - _position);

            if (count > available)
                count = available;

            if (_stream.CanSeek)
                _stream.Position = _offset + _position;

            int bytesRead = await _stream.ReadAsync(buffer.AsMemory(offset, count), cancellationToken);
            _position += bytesRead;

            return bytesRead;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.Length < 1)
                return 0;

            if (_position >= _length)
                return 0;

            int available = Convert.ToInt32(_length - _position);

            if (buffer.Length > available)
                buffer = buffer.Slice(0, available);

            if (_stream.CanSeek)
                _stream.Position = _offset + _position;

            int bytesRead = await _stream.ReadAsync(buffer, cancellationToken);
            _position += bytesRead;

            return bytesRead;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            if (!_stream.CanSeek)
                throw new InvalidOperationException("Stream is not seekable.");

            long pos;

            switch (origin)
            {
                case SeekOrigin.Begin:
                    pos = offset;
                    break;

                case SeekOrigin.Current:
                    pos = _position + offset;
                    break;

                case SeekOrigin.End:
                    pos = _length + offset;
                    break;

                default:
                    throw new InvalidOperationException();
            }

            if ((pos < 0) || (pos >= _length))
                throw new EndOfStreamException("OffsetStream reached begining/end of stream.");

            _position = pos;
            _stream.Position = _offset + _position;

            if (_position > _length)
                _length = _position;

            return pos;
        }

        public override void SetLength(long value)
        {
            if (_readOnly)
                throw new InvalidOperationException("OffsetStream is read only.");

            _stream.SetLength(_offset + value);
            _length = value;

            if (_position > _length)
            {
                _position = _length;
                _stream.Position = _offset + _position;
            }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (_readOnly)
                throw new InvalidOperationException("OffsetStream is read only.");

            if (count < 1)
                return;

            if (_stream.CanSeek)
                _stream.Position = _offset + _position;

            _stream.Write(buffer, offset, count);
            _position += count;

            if (_position > _length)
                _length = _position;
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (_readOnly)
                throw new InvalidOperationException("OffsetStream is read only.");

            if (count < 1)
                return;

            if (_stream.CanSeek)
                _stream.Position = _offset + _position;

            await _stream.WriteAsync(buffer.AsMemory(offset, count), cancellationToken);
            _position += count;

            if (_position > _length)
                _length = _position;
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_readOnly)
                throw new InvalidOperationException("OffsetStream is read only.");

            if (buffer.Length < 1)
                return;

            if (_stream.CanSeek)
                _stream.Position = _offset + _position;

            await _stream.WriteAsync(buffer, cancellationToken);
            _position += buffer.Length;

            if (_position > _length)
                _length = _position;
        }

        #endregion

        #region public special

        public long BaseStreamOffset
        { get { return _offset; } }

        public Stream BaseStream
        { get { return _stream; } }

        public void WriteTo(Stream s)
        {
            WriteTo(s, 4096);
        }

        public void WriteTo(Stream stream, int bufferSize)
        {
            if (!_stream.CanSeek)
                throw new InvalidOperationException("Stream is not seekable.");

            if (_length < bufferSize)
                bufferSize = Convert.ToInt32(_length);

            long previousPosition = _position;
            _position = 0;
            _stream.Position = _offset;

            try
            {
                CopyTo(stream, bufferSize);
            }
            finally
            {
                _position = previousPosition;
                _stream.Position = _offset + _position;
            }
        }

        public Task WriteToAsync(Stream s)
        {
            return WriteToAsync(s, 4096);
        }

        public async Task WriteToAsync(Stream stream, int bufferSize)
        {
            if (!_stream.CanSeek)
                throw new InvalidOperationException("Stream is not seekable.");

            if (_length < bufferSize)
                bufferSize = Convert.ToInt32(_length);

            long previousPosition = _position;
            _position = 0;
            _stream.Position = _offset;

            try
            {
                await CopyToAsync(stream, bufferSize);
            }
            finally
            {
                _position = previousPosition;
                _stream.Position = _offset + _position;
            }
        }

        #endregion
    }
}
