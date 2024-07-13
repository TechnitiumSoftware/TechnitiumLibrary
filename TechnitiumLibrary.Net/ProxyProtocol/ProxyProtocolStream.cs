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
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.ProxyProtocol
{
    public class ProxyProtocolStream : Stream
    {
        #region variables

        readonly Stream _baseStream;

        readonly byte[] _buffer = new byte[256];
        int _offset;
        int _dataOffset;
        int _length;

        int _protocolVersion;
        bool _isLocal;
        AddressFamily _addressFamily;
        SocketType _socketType;
        IPAddress _sourceAddress;
        IPAddress _destinationAddress;
        ushort _sourcePort;
        ushort _destinationPort;

        #endregion

        #region constructor

        private ProxyProtocolStream(Stream baseStream)
        {
            _baseStream = baseStream;
        }

        #endregion

        #region IDisposable

        bool _disposed = false;

        protected override void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
                _baseStream?.Dispose();

            _disposed = true;

            base.Dispose(disposing);
        }

        #endregion

        #region static

        public async static Task<ProxyProtocolStream> CreateAsServerAsync(Stream baseStream, CancellationToken cancellationToken = default)
        {
            ProxyProtocolStream proxy = new ProxyProtocolStream(baseStream);

            int bytesRead;

            do
            {
                bytesRead = await baseStream.ReadAsync(proxy._buffer.AsMemory(proxy._length, proxy._buffer.Length - proxy._length), cancellationToken);
                if (bytesRead < 1)
                    throw new EndOfStreamException();

                proxy._length += bytesRead;
                proxy._offset = proxy._length - bytesRead;

                if (proxy._length < 8)
                    continue;

                if (
                    (proxy._buffer[0] == 0x50) &&
                    (proxy._buffer[1] == 0x52) &&
                    (proxy._buffer[2] == 0x4F) &&
                    (proxy._buffer[3] == 0x58) &&
                    (proxy._buffer[4] == 0x59)
                   )
                {
                    proxy._protocolVersion = 1;
                    break;
                }

                if (proxy._length < 16)
                    continue;

                if (
                    (proxy._buffer[0] == 0x0D) &&
                    (proxy._buffer[1] == 0x0A) &&
                    (proxy._buffer[2] == 0x0D) &&
                    (proxy._buffer[3] == 0x0A) &&
                    (proxy._buffer[4] == 0x00) &&
                    (proxy._buffer[5] == 0x0D) &&
                    (proxy._buffer[6] == 0x0A) &&
                    (proxy._buffer[7] == 0x51) &&
                    (proxy._buffer[8] == 0x55) &&
                    (proxy._buffer[9] == 0x49) &&
                    (proxy._buffer[10] == 0x54) &&
                    (proxy._buffer[11] == 0x0A)
                   )
                {
                    int version = proxy._buffer[12] >> 4;
                    if (version != 2)
                        throw new NotSupportedException("PROXY protocol version is not supported: " + version);

                    proxy._protocolVersion = 2;
                    break;
                }

                throw new InvalidDataException("The stream does not contain PROXY protocol header.");
            }
            while (proxy._length < proxy._buffer.Length);

            do
            {
                switch (proxy._protocolVersion)
                {
                    case 1:
                        for (int i = proxy._offset; i < proxy._length - 1; i++)
                        {
                            if (
                                (proxy._buffer[i] == '\r') &&
                                (proxy._buffer[i + 1] == '\n')
                               )
                            {
                                proxy.ParseVersion1(Encoding.ASCII.GetString(proxy._buffer, 0, i));
                                proxy._offset = i + 2;
                                proxy._dataOffset = proxy._offset;

                                return proxy;
                            }
                        }
                        break;

                    case 2:
                        int addressLength = proxy._buffer[14] << 8 | proxy._buffer[15];
                        if (proxy._length < addressLength)
                            break;

                        proxy.ParseVersion2();
                        proxy._offset = 16 + addressLength;
                        proxy._dataOffset = proxy._offset;

                        return proxy;

                    default:
                        throw new InvalidOperationException();
                }

                bytesRead = await baseStream.ReadAsync(proxy._buffer.AsMemory(proxy._length, proxy._buffer.Length - proxy._length), cancellationToken);
                if (bytesRead < 1)
                    throw new EndOfStreamException();

                proxy._length += bytesRead;
                proxy._offset = proxy._length - bytesRead;
            }
            while (proxy._length < proxy._buffer.Length);

            throw new InvalidDataException("Failed to parse PROXY protocol from the stream.");
        }

        #endregion

        #region private

        private static string PopWord(ref string line)
        {
            if (line.Length == 0)
                return line;

            int i = line.IndexOf(' ');
            string word;

            if (i < 0)
            {
                word = line;
                line = "";
            }
            else
            {
                word = line.Substring(0, i);
                line = line.Substring(i + 1);
            }

            return word;
        }

        private void ParseVersion1(string value)
        {
            //PROXY TCP4 192.168.0.1 192.168.0.11 56324 443
            _ = PopWord(ref value);
            string addressFamily = PopWord(ref value);
            string sourceAddress = PopWord(ref value);
            string destinationAddress = PopWord(ref value);
            string sourcePort = PopWord(ref value);
            string destinationPort = PopWord(ref value);

            switch (addressFamily.ToUpperInvariant())
            {
                case "TCP4":
                    _addressFamily = AddressFamily.InterNetwork;
                    break;

                case "TCP6":
                    _addressFamily = AddressFamily.InterNetworkV6;
                    break;

                case "UNKNOWN":
                    _addressFamily = AddressFamily.Unknown;
                    break;

                default:
                    throw new NotSupportedException("PROXY protocol address family is not supported: " + addressFamily);
            }

            _socketType = SocketType.Stream;
            _sourceAddress = IPAddress.Parse(sourceAddress);
            _destinationAddress = IPAddress.Parse(destinationAddress);
            _sourcePort = ushort.Parse(sourcePort);
            _destinationPort = ushort.Parse(destinationPort);
        }

        private void ParseVersion2()
        {
            int command = _buffer[12] & 0x0F;
            int addressFamily = _buffer[13] >> 4;
            int protocol = _buffer[13] & 0x0F;
            int addressLength = _buffer[14] << 8 | _buffer[15];

            switch (command)
            {
                case 0: //local
                    _isLocal = true;
                    break;

                case 1: //proxy
                    _isLocal = false;
                    break;

                default:
                    throw new NotSupportedException();
            }

            switch (addressFamily)
            {
                case 0:
                    _addressFamily = AddressFamily.Unspecified;
                    break;

                case 1:
                    _addressFamily = AddressFamily.InterNetwork;

                    if (addressLength >= 12)
                    {
                        _sourceAddress = new IPAddress(new Span<byte>(_buffer, 16, 4));
                        _destinationAddress = new IPAddress(new Span<byte>(_buffer, 20, 4));
                        _sourcePort = (ushort)(_buffer[24] << 8 | _buffer[25]);
                        _destinationPort = (ushort)(_buffer[26] << 8 | _buffer[27]);
                    }
                    break;

                case 2:
                    _addressFamily = AddressFamily.InterNetworkV6;

                    if (addressLength >= 36)
                    {
                        _sourceAddress = new IPAddress(new Span<byte>(_buffer, 16, 16));
                        _destinationAddress = new IPAddress(new Span<byte>(_buffer, 32, 16));
                        _sourcePort = (ushort)(_buffer[48] << 8 | _buffer[49]);
                        _destinationPort = (ushort)(_buffer[50] << 8 | _buffer[51]);
                    }
                    break;

                case 3:
                    _addressFamily = AddressFamily.Unix;
                    break;

                default:
                    throw new NotSupportedException();
            }

            switch (protocol)
            {
                case 0:
                    _socketType = SocketType.Unknown;
                    break;

                case 1:
                    _socketType = SocketType.Stream;
                    break;

                case 2:
                    _socketType = SocketType.Dgram;
                    break;

                default:
                    throw new NotSupportedException();
            }
        }

        #endregion

        #region stream

        public override bool CanRead
        { get { return _baseStream.CanRead; } }

        public override bool CanSeek
        { get { return false; } }

        public override bool CanWrite
        { get { return _baseStream.CanWrite; } }

        public override bool CanTimeout
        { get { return _baseStream.CanTimeout; } }

        public override long Length
        { get { throw new NotSupportedException(); } }

        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Flush()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            _baseStream.Flush();
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            return _baseStream.FlushAsync(cancellationToken);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_offset < _length)
            {
                int bytesAvailable = _length - _offset;
                if (bytesAvailable < count)
                    count = bytesAvailable;

                Buffer.BlockCopy(_buffer, _offset, buffer, offset, count);
                _offset += count;

                return count;
            }

            return _baseStream.Read(buffer, offset, count);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (_offset < _length)
            {
                int bytesAvailable = _length - _offset;
                if (bytesAvailable < count)
                    count = bytesAvailable;

                Buffer.BlockCopy(_buffer, _offset, buffer, offset, count);
                _offset += count;

                return Task.FromResult(count);
            }

            return _baseStream.ReadAsync(buffer, offset, count, cancellationToken);
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_offset < _length)
            {
                int bytesAvailable = _length - _offset;
                if (bytesAvailable < buffer.Length)
                    buffer = buffer.Slice(0, bytesAvailable);

                _buffer.AsMemory(_offset, buffer.Length).CopyTo(buffer);
                _offset += buffer.Length;

                return ValueTask.FromResult(buffer.Length);
            }

            return _baseStream.ReadAsync(buffer, cancellationToken);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            _baseStream.Write(buffer, offset, count);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            return _baseStream.WriteAsync(buffer, offset, count, cancellationToken);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            return _baseStream.WriteAsync(buffer, cancellationToken);
        }

        #endregion

        #region properties

        public int DataOffset
        { get { return _dataOffset; } }

        public int ProtocolVersion
        { get { return _protocolVersion; } }

        public bool IsLocal
        { get { return _isLocal; } }

        public AddressFamily AddressFamily
        { get { return _addressFamily; } }

        public SocketType SocketType
        { get { return _socketType; } }

        public IPAddress SourceAddress
        { get { return _sourceAddress; } }

        public IPAddress DestinationAddress
        { get { return _destinationAddress; } }

        public ushort SourcePort
        { get { return _sourcePort; } }

        public ushort DestinationPort
        { get { return _destinationPort; } }

        #endregion
    }
}
