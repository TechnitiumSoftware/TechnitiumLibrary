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
using System.IO;

namespace TechnitiumLibrary.IO
{
    [Obsolete]
    public class FixMemoryStream : Stream
    {
        #region variables

        byte[] _buffer;
        int _position;
        int _length;

        #endregion

        #region constructor

        public FixMemoryStream(int capacity)
        {
            _buffer = new byte[capacity];
            _position = 0;
            _length = 0;
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
        {
            return;
        }

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
                throw new ArgumentOutOfRangeException("Count cannot be less than 1.");

            if (_position >= _length)
                return 0;

            if (count > (_length - _position))
                count = Convert.ToInt32(_length - _position);

            System.Buffer.BlockCopy(_buffer, _position, buffer, offset, count);
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
                throw new EndOfStreamException("Stream reached begining/end of stream.");
            else
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
                throw new EndOfStreamException("Stream reached end of stream.");

            System.Buffer.BlockCopy(buffer, offset, _buffer, _position, count);
            _position = pos;

            if (_position > _length)
                _length = _position;
        }

        #endregion

        #region public

        public byte[] ToArray()
        {
            byte[] buffer = new byte[_length];

            System.Buffer.BlockCopy(_buffer, 0, buffer, 0, _length);

            return buffer;
        }

        #endregion

        #region properties

        public byte[] Buffer
        { get { return _buffer; } }

        public int Capacity
        { get { return _buffer.Length; } }

        #endregion
    }
}
