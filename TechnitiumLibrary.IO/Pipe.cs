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

            byte[] _buffer;
            int _offset;
            int _count;

            int _readTimeout = Timeout.Infinite;
            int _writeTimeout = Timeout.Infinite;

            PipeStream _otherPipe;

            #endregion

            #region constructor

            private PipeStream()
            { }

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
                return _otherPipe.ReadBuffer(buffer, offset, count, _readTimeout);
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                lock (this)
                {
                    _buffer = buffer;
                    _offset = offset;
                    _count = count;

                    Monitor.Pulse(this);

                    if (!Monitor.Wait(this, _writeTimeout))
                        throw new IOException("Write timed out.");
                }
            }

            #endregion

            #region private

            private int ReadBuffer(byte[] buffer, int offset, int count, int timeout)
            {
                lock (this)
                {
                    if (_buffer == null)
                    {
                        if (!Monitor.Wait(this, timeout))
                            throw new IOException("Read timed out.");

                        if (_buffer == null)
                            return 0;
                    }

                    int bytesCopied = count;

                    if (bytesCopied > _count)
                        bytesCopied = _count;

                    Buffer.BlockCopy(_buffer, _offset, buffer, offset, bytesCopied);

                    if (bytesCopied < _count)
                    {
                        _offset += bytesCopied;
                        _count -= bytesCopied;
                    }
                    else
                    {
                        _buffer = null;

                        Monitor.Pulse(this);
                    }

                    return bytesCopied;
                }
            }

            #endregion
        }
    }
}
