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

namespace TechnitiumLibrary.IO
{
    public class ByteArrayStream : Stream
    {
        #region variables

        readonly byte[] _buffer;
        int _position;
        int _length;

        #endregion

        #region constructor

        public ByteArrayStream(byte[] buffer)
        {
            _buffer = buffer;
            _length = buffer.Length;
        }

        #endregion

        #region stream support

        public override bool CanRead
        { get { return true; } }

        public override bool CanSeek
        { get { return true; } }

        public override bool CanWrite
        { get { return true; } }

        public override void Flush()
        { }

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
                if (value > _buffer.Length)
                    throw new EndOfStreamException();

                _position = Convert.ToInt32(value);

                if (_position > _length)
                    _length = _position;
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (count < 1)
                throw new IOException("Count must be atleast 1 byte.");

            if (_position >= _length)
                return 0;

            int available = _length - _position;

            if (count > available)
                count = available;

            Buffer.BlockCopy(_buffer, _position, buffer, offset, count);
            _position += count;

            return count;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
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
                throw new EndOfStreamException();

            _position = Convert.ToInt32(pos);

            return pos;
        }

        public override void SetLength(long value)
        {
            if ((value > _buffer.Length) || (value < 0))
                throw new EndOfStreamException();

            _length = Convert.ToInt32(value);

            if (_position > _length)
                _position = _length;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (count < 1)
                return;

            int pos = _position + count;

            if (pos > _buffer.Length)
                throw new EndOfStreamException();

            Buffer.BlockCopy(buffer, offset, _buffer, _position, count);
            _position = pos;

            if (_position > _length)
                _length = _position;
        }

        #endregion
    }
}
