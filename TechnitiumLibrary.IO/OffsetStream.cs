/*
Technitium Library
Copyright (C) 2018  Shreyas Zare (shreyas@technitium.com)

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

namespace TechnitiumLibrary.IO
{
    public class OffsetStream : Stream
    {
        #region variables

        Stream _stream;
        long _offset;
        long _length;
        long _position;
        bool _readOnly;
        bool _ownStream;

        #endregion

        #region constructor

        public OffsetStream(Stream stream, long offset = 0, long length = 0, bool readOnly = false, bool ownStream = false)
        {
            if (stream.CanSeek)
            {
                if (offset > stream.Length)
                    throw new EndOfStreamException();
                else
                    _offset = offset;

                if (length > (stream.Length - offset))
                    throw new EndOfStreamException();
                else if (length == 0)
                    _length = stream.Length - offset;
                else
                    _length = length;
            }
            else
            {
                _offset = 0;
                _length = length;
            }

            _stream = stream;
            _readOnly = readOnly;
            _ownStream = ownStream;
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
                if (_ownStream & (_stream != null))
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
        { get { return (_stream.CanWrite && !_readOnly); } }

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
                if (value > _length)
                    throw new EndOfStreamException();

                if (!_stream.CanSeek)
                    throw new NotSupportedException("Cannot seek stream.");

                _position = value;
            }
        }

        public override void Flush()
        {
            if (_readOnly)
                throw new IOException("OffsetStream is read only.");

            _stream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (count < 1)
                throw new ArgumentOutOfRangeException("Count cannot be less than 1.");

            if (_position >= _length)
                return 0;

            if (count > (_length - _position))
                count = Convert.ToInt32(_length - _position);

            if (_stream.CanSeek)
                _stream.Position = _offset + _position;

            int bytesRead = _stream.Read(buffer, offset, count);
            _position += bytesRead;

            return bytesRead;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            if (!_stream.CanSeek)
                throw new IOException("Stream is not seekable.");

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
                    pos = 0;
                    break;
            }

            if ((pos < 0) || (pos >= _length))
                throw new EndOfStreamException("OffsetStream reached begining/end of stream.");

            _position = pos;

            return pos;
        }

        public override void SetLength(long value)
        {
            if (_readOnly)
                throw new IOException("OffsetStream is read only.");

            _stream.SetLength(_offset + value);
            _length = value;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (_readOnly)
                throw new IOException("OffsetStream is read only.");

            if (count < 1)
                return;

            long pos = _position + count;

            if (pos > _length)
                throw new EndOfStreamException("OffsetStream reached end of stream.");

            if (_stream.CanSeek)
                _stream.Position = _offset + _position;

            _stream.Write(buffer, offset, count);
            _position = pos;
        }

        #endregion

        #region public special

        public long BaseStreamOffset
        { get { return _offset; } }

        public Stream BaseStream
        { get { return _stream; } }

        public void Reset(long offset, long length, long position)
        {
            _offset = offset;
            _length = length;
            _position = position;
        }

        public void WriteTo(Stream s)
        {
            WriteTo(s, 4096);
        }

        public void WriteTo(Stream stream, int bufferSize)
        {
            if (!_stream.CanSeek)
                throw new IOException("Stream is not seekable.");

            if (_length < bufferSize)
                bufferSize = Convert.ToInt32(_length);

            long previousPosition = _position;
            _position = 0;

            try
            {
                this.CopyTo(stream, bufferSize);
            }
            finally
            {
                _position = previousPosition;
            }
        }

        #endregion
    }
}
