/*
Technitium Library
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public abstract class DnsResourceRecordData
    {
        #region variables

        protected ushort _rdLength;
        readonly bool _emptyRData;

        #endregion

        #region constructor

        protected DnsResourceRecordData()
        { }

        protected DnsResourceRecordData(Stream s)
        {
            //read RDLENGTH
            _rdLength = DnsDatagram.ReadUInt16NetworkOrder(s);

            //read RDATA from a window so a short or long length cannot pull in the next record.
            //compression pointers may still seek into the rest of the message.
            long rdataStart = s.Position;
            ReadRecordData(new DnsRDataStream(s, _rdLength));

            long rdataEnd = rdataStart + _rdLength;
            if (s.Position != rdataEnd)
                throw new DnsClientException("RDATA length does not match RDLENGTH.");

            if (_rdLength == 0)
                _emptyRData = true;
        }

        #endregion

        #region protected

        protected abstract void ReadRecordData(Stream s);

        protected abstract void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm);

        #endregion

        #region internal

        internal virtual void NormalizeName()
        { }

        internal void WriteCanonicalRecordData(Stream s)
        {
            WriteRecordData(s, null, true);
        }

        internal abstract string ToZoneFileEntry(string originDomain = null);

        #endregion

        #region public

        public void WriteTo(Stream s)
        {
            WriteTo(s, null);
        }

        public void WriteTo(Stream s, List<DnsDomainOffset> domainEntries)
        {
            if (_emptyRData)
            {
                Span<byte> buffer = stackalloc byte[2];
                s.Write(buffer);
            }
            else
            {
                long originalPosition = s.Position;

                //write dummy RDLENGTH
                s.Position += 2;

                //write RDATA
                WriteRecordData(s, domainEntries, false);

                long finalPosition = s.Position;

                //write actual RDLENGTH
                ushort length = Convert.ToUInt16(finalPosition - originalPosition - 2);
                s.Position = originalPosition;
                DnsDatagram.WriteUInt16NetworkOrder(length, s);

                s.Position = finalPosition;
            }
        }

        public override abstract bool Equals(object obj);

        public override abstract int GetHashCode();

        public override string ToString()
        {
            return ToZoneFileEntry();
        }

        public abstract void SerializeTo(Utf8JsonWriter jsonWriter);

        #endregion

        #region properties

        public ushort RDLENGTH
        { get { return _rdLength; } }

        public abstract int UncompressedLength
        { get; }

        #endregion

        sealed class DnsRDataStream : Stream
        {
            readonly Stream _inner;
            readonly long _start;
            readonly long _end;

            public DnsRDataStream(Stream inner, int length)
            {
                _inner = inner;
                _start = inner.Position;
                _end = _start + length;
            }

            public override bool CanRead
            { get { return _inner.CanRead; } }

            public override bool CanSeek
            { get { return _inner.CanSeek; } }

            public override bool CanWrite
            { get { return false; } }

            public override long Length
            { get { return _inner.Length; } }

            public override long Position
            {
                get { return _inner.Position; }
                set { _inner.Position = value; }
            }

            public override void Flush()
            { }

            public override int Read(byte[] buffer, int offset, int count)
            {
                return Read(buffer.AsSpan(offset, count));
            }

            public override int Read(Span<byte> buffer)
            {
                long position = _inner.Position;
                if (position >= _end)
                    return 0;

                if (position >= _start)
                {
                    long remaining = _end - position;
                    if (remaining < buffer.Length)
                        buffer = buffer.Slice(0, (int)remaining);
                }

                return _inner.Read(buffer);
            }

            public override int ReadByte()
            {
                if (_inner.Position >= _end)
                    return -1;

                return _inner.ReadByte();
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                return _inner.Seek(offset, origin);
            }

            public override void SetLength(long value)
            {
                throw new NotSupportedException();
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                throw new NotSupportedException();
            }
        }
    }
}
