/*
Technitium Library
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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

namespace TechnitiumLibrary.IO
{
    public class Pipe
    {
        #region variables

        PipeStream[] _streamCouple;

        #endregion

        #region constructor

        public Pipe()
        {
            _streamCouple = PipeStream.CreatePipeStreamCouple();
        }

        #endregion

        #region properties

        public Stream Stream1
        { get { return _streamCouple[0]; } }

        public Stream Stream2
        { get { return _streamCouple[1]; } }

        #endregion

        private class PipeStream : Stream
        {
            #region variables

            const int MAX_BUFFER_SIZE = 64 * 1024;

            readonly object _bufferLock = new object();
            byte[] _buffer = new byte[MAX_BUFFER_SIZE];
            int _position;
            int _length;

            int _readTimeout = Timeout.Infinite;
            int _writeTimeout = Timeout.Infinite;

            PipeStream _otherPipe;

            #endregion

            #region constructor

            private PipeStream()
            { }

            #endregion

            #region IDisposable

            bool _disposed;

            protected override void Dispose(bool disposing)
            {
                try
                {
                    lock (_bufferLock)
                    {
                        if (_disposed)
                            return;

                        _disposed = true;

                        Monitor.Pulse(_bufferLock);
                    }

                    _otherPipe.Dispose();
                }
                finally
                {
                    base.Dispose(disposing);
                }
            }

            #endregion

            #region static

            public static PipeStream[] CreatePipeStreamCouple()
            {
                PipeStream stream1 = new PipeStream();
                PipeStream stream2 = new PipeStream();

                stream1._otherPipe = stream2;
                stream2._otherPipe = stream1;

                return new PipeStream[] { stream1, stream2 };
            }

            #endregion

            #region stream support

            public override bool CanRead
            {
                get { return true; }
            }

            public override bool CanSeek
            {
                get { return false; }
            }

            public override bool CanWrite
            {
                get { return true; }
            }

            public override bool CanTimeout
            {
                get { return true; }
            }

            public override int ReadTimeout
            {
                get { return _readTimeout; }
                set { _readTimeout = value; }
            }

            public override int WriteTimeout
            {
                get { return _writeTimeout; }
                set { _writeTimeout = value; }
            }

            public override void Flush()
            {
                //do nothing
            }

            public override long Length
            {
                get { throw new IOException("Pipe stream does not support seeking."); }
            }

            public override long Position
            {
                get
                {
                    throw new IOException("Pipe stream does not support seeking.");
                }
                set
                {
                    throw new IOException("Pipe stream does not support seeking.");
                }
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new IOException("Pipe stream does not support seeking.");
            }

            public override void SetLength(long value)
            {
                throw new IOException("Pipe stream does not support seeking.");
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (count < 1)
                    throw new ArgumentOutOfRangeException("Count cannot be less than 1.");

                return _otherPipe.ReadBuffer(buffer, offset, count, _readTimeout);
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                if (count > 0)
                {
                    lock (_bufferLock)
                    {
                        if (_disposed)
                            throw new ObjectDisposedException("DataStream");

                        while (_length + count > _buffer.Length)
                        {
                            if (!Monitor.Wait(_bufferLock, _writeTimeout))
                                throw new IOException("Write timed out.");

                            if (_disposed)
                                throw new ObjectDisposedException("DataStream");
                        }

                        Buffer.BlockCopy(buffer, offset, _buffer, _length, count);
                        _length += count;

                        Monitor.Pulse(_bufferLock);
                    }
                }
            }

            #endregion

            #region private

            private int ReadBuffer(byte[] buffer, int offset, int count, int timeout)
            {
                lock (_bufferLock)
                {
                    int bytesAvailable = _length - _position;
                    if (bytesAvailable < 1)
                    {
                        if (_disposed)
                            return 0;

                        if (!Monitor.Wait(_bufferLock, timeout))
                            throw new IOException("Read timed out.");

                        bytesAvailable = _length - _position;
                        if (bytesAvailable < 1)
                            return 0;
                    }

                    if (count > bytesAvailable)
                        count = bytesAvailable;

                    Buffer.BlockCopy(_buffer, _position, buffer, offset, count);

                    _position += count;

                    if (_position >= _length)
                    {
                        _position = 0;
                        _length = 0;

                        Monitor.Pulse(_bufferLock);
                    }

                    return count;
                }
            }

            #endregion
        }
    }
}
