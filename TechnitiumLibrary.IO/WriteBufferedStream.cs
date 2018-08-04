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
    public class WriteBufferedStream : Stream
    {
        #region variables

        readonly Stream _baseStream;
        readonly byte[] _writeBuffer;
        int _writeBufferPosition;

        #endregion

        #region constructor

        public WriteBufferedStream(Stream baseStream, int bufferSize = 4096)
        {
            if (!baseStream.CanWrite)
                throw new ArgumentException("baseStream not writeable.");

            _baseStream = baseStream;
            _writeBuffer = new byte[bufferSize];
        }

        #endregion

        #region IDisposable

        private bool _disposed = false;

        protected override void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_baseStream != null)
                    _baseStream.Dispose();
            }

            _disposed = true;

            base.Dispose(disposing);
        }

        #endregion

        #region stream support

        public override bool CanRead
        { get { return _baseStream.CanRead; } }

        public override bool CanSeek
        { get { return false; } }

        public override bool CanWrite
        { get { return _baseStream.CanWrite; } }

        public override bool CanTimeout
        { get { return _baseStream.CanTimeout; } }

        public override int ReadTimeout
        {
            get { return _baseStream.ReadTimeout; }
            set { _baseStream.ReadTimeout = value; }
        }

        public override int WriteTimeout
        {
            get { return _baseStream.WriteTimeout; }
            set { _baseStream.WriteTimeout = value; }
        }

        public override void Flush()
        {
            if (!_baseStream.CanWrite)
                throw new ObjectDisposedException("WriteBufferedStream");

            if (_writeBufferPosition > 0)
            {
                _baseStream.Write(_writeBuffer, 0, _writeBufferPosition);
                _baseStream.Flush();

                _writeBufferPosition = 0;
            }
        }

        public override long Length
        { get { return _baseStream.Length; } }

        public override long Position
        {
            get
            { return _baseStream.Position; }
            set
            { throw new NotSupportedException(); }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return _baseStream.Read(buffer, offset, count);
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
            if (!_baseStream.CanWrite)
                throw new ObjectDisposedException("WriteBufferedStream");

            int bytesAvailable;

            while (count > 0)
            {
                bytesAvailable = _writeBuffer.Length - _writeBufferPosition;

                if (bytesAvailable > count)
                {
                    //copy to buffer
                    Buffer.BlockCopy(buffer, offset, _writeBuffer, _writeBufferPosition, count);

                    _writeBufferPosition += count;
                    offset += count;
                    count = 0;
                }
                else
                {
                    //fill buffer to brim                    
                    Buffer.BlockCopy(buffer, offset, _writeBuffer, _writeBufferPosition, bytesAvailable);

                    _writeBufferPosition += bytesAvailable;
                    offset += bytesAvailable;
                    count -= bytesAvailable;

                    //flush buffer
                    Flush();
                }
            }
        }

        #endregion
    }
}
