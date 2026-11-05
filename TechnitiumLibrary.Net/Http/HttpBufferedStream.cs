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
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.Http
{
    class HttpBufferedStream : Stream
    {
        #region variables

        readonly static ConditionalWeakTable<Stream, HttpBufferedStream> _streams = new ConditionalWeakTable<Stream, HttpBufferedStream>();

        readonly Stream _baseStream;

        byte[] _pending;
        int _pendingOffset;
        int _pendingCount;

        #endregion

        #region constructor

        private HttpBufferedStream(Stream baseStream)
        {
            _baseStream = baseStream;
        }

        #endregion

        #region static

        internal static HttpBufferedStream Get(Stream stream)
        {
            if (stream is HttpBufferedStream bufferedStream)
                return bufferedStream;

            return _streams.GetValue(stream, static s => new HttpBufferedStream(s));
        }

        internal static byte[] TakePending(Stream stream)
        {
            if (stream is HttpBufferedStream bufferedStream)
                return bufferedStream.TakePending();

            if (_streams.TryGetValue(stream, out HttpBufferedStream existing))
                return existing.TakePending();

            return Array.Empty<byte>();
        }

        #endregion

        #region private

        internal void Unread(byte[] buffer, int offset, int count)
        {
            if (count < 1)
                return;

            byte[] combined = new byte[count + _pendingCount];
            Buffer.BlockCopy(buffer, offset, combined, 0, count);

            if (_pendingCount > 0)
                Buffer.BlockCopy(_pending, _pendingOffset, combined, count, _pendingCount);

            _pending = combined;
            _pendingOffset = 0;
            _pendingCount = combined.Length;
        }

        internal byte[] TakePending()
        {
            if (_pendingCount < 1)
                return Array.Empty<byte>();

            byte[] data = new byte[_pendingCount];
            Buffer.BlockCopy(_pending, _pendingOffset, data, 0, _pendingCount);
            _pendingCount = 0;
            return data;
        }

        int Drain(Span<byte> destination)
        {
            if ((_pendingCount < 1) || destination.IsEmpty)
                return 0;

            int count = Math.Min(destination.Length, _pendingCount);
            _pending.AsSpan(_pendingOffset, count).CopyTo(destination);
            _pendingOffset += count;
            _pendingCount -= count;
            return count;
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

        public override int Read(Span<byte> buffer)
        {
            int pending = Drain(buffer);
            if (pending > 0)
                return pending;

            return _baseStream.Read(buffer);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return Read(buffer.AsSpan(offset, count));
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int pending = Drain(buffer.Span);
            if (pending > 0)
                return new ValueTask<int>(pending);

            return _baseStream.ReadAsync(buffer, cancellationToken);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            int pending = Drain(buffer.AsSpan(offset, count));
            if (pending > 0)
                return Task.FromResult(pending);

            return _baseStream.ReadAsync(buffer, offset, count, cancellationToken);
        }

        #endregion
    }
}
