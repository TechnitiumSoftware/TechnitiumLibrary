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
using System.Text.Json;

namespace TechnitiumLibrary.Net.Dns.EDnsOptions
{
    /// <summary>
    /// RFC 7873 DNS COOKIE EDNS option.
    /// Option data:
    /// - Client cookie: 8 bytes (MUST)
    /// - Server cookie: 0 or 8-32 bytes (MAY)
    /// Total option data length: 8 OR 16-40 bytes.
    /// </summary>
    public class EDnsCookieOptionData : EDnsOptionData
    {
        #region variables

        public const int CLIENT_COOKIE_LENGTH = 8;
        public const int SERVER_COOKIE_MAX_LENGTH = 32;
        public const int SERVER_COOKIE_MIN_LENGTH = 8;
        byte[] _clientCookie;
        byte[] _serverCookie; //null means absent (client-cookie-only)
        byte[] _malformedData; //preserved wire data for server-side RFC 7873 FORMERR handling

        #endregion

        #region constructor

        public EDnsCookieOptionData(byte[] clientCookie, byte[] serverCookie = null)
        {
            ArgumentNullException.ThrowIfNull(clientCookie);

            if (clientCookie.Length != CLIENT_COOKIE_LENGTH)
                throw new ArgumentException("Client cookie must be 8 bytes.", nameof(clientCookie));

            if (serverCookie is not null &&
                (serverCookie.Length < SERVER_COOKIE_MIN_LENGTH || serverCookie.Length > SERVER_COOKIE_MAX_LENGTH))
                throw new ArgumentException("Server cookie must be 8-32 bytes.", nameof(serverCookie));

            _clientCookie = (byte[])clientCookie.Clone();
            _serverCookie = serverCookie is null ? null : (byte[])serverCookie.Clone();
        }

        /// <summary>
        /// Parsing ctor. The stream is positioned at OPTION-LENGTH (immediately after OPTION-CODE),
        /// because EDnsOption(Stream) already read OPTION-CODE.
        /// </summary>
        public EDnsCookieOptionData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadOptionData(Stream s)
        {
            // RFC 7873 §5.2.2 requires the server to return FORMERR for a malformed
            // COOKIE length. Preserve and consume the malformed payload so that the
            // complete DNS datagram reaches the server's COOKIE classifier instead of
            // aborting EDNS parsing and surfacing as a transport exception.
            int serverLen = _length - CLIENT_COOKIE_LENGTH;
            if (_length < CLIENT_COOKIE_LENGTH ||
                (serverLen != 0 && (serverLen < SERVER_COOKIE_MIN_LENGTH || serverLen > SERVER_COOKIE_MAX_LENGTH)))
            {
                _malformedData = new byte[_length];
                s.ReadExactly(_malformedData);
                return;
            }

            _clientCookie = new byte[CLIENT_COOKIE_LENGTH];
            s.ReadExactly(_clientCookie);

            if (serverLen == 0)
            {
                _serverCookie = null;
                return;
            }

            _serverCookie = new byte[serverLen];
            s.ReadExactly(_serverCookie);
        }

        protected override void WriteOptionData(Stream s)
        {
            if (_malformedData is not null)
            {
                s.Write(_malformedData);
                return;
            }

            s.Write(_clientCookie);

            if (_serverCookie is not null)
                s.Write(_serverCookie);
        }

        #endregion

        #region public

        public bool Equals(EDnsCookieOptionData other)
        {
            if (other is null)
                return false;

            if (ReferenceEquals(this, other))
                return true;

            if (_malformedData is not null || other._malformedData is not null)
                return _malformedData is not null && other._malformedData is not null && _malformedData.AsSpan().SequenceEqual(other._malformedData);

            // A server cookie is either absent or 8-32 bytes - never a zero-length array -
            // so mapping null to an empty span decides the absent cases correctly too.
            return _clientCookie.AsSpan().SequenceEqual(other._clientCookie) &&
                _serverCookie.AsSpan().SequenceEqual(other._serverCookie);
        }

        public override bool Equals(object obj) => Equals(obj as EDnsCookieOptionData);

        public override int GetHashCode()
        {
            HashCode hash = new();

            // AddBytes keeps the byte order significant. CollectionExtensions.GetArrayHashCode
            // would read better here but XORs its elements, which collides heavily on the
            // short, near-sequential byte runs cookies are made of.
            if (_malformedData is not null)
            {
                hash.AddBytes(_malformedData);
                return hash.ToHashCode();
            }

            hash.AddBytes(_clientCookie);

            // A null server cookie converts to an empty span, which contributes nothing.
            hash.AddBytes(_serverCookie);

            return hash.ToHashCode();
        }

        public override void SerializeTo(Utf8JsonWriter writer)
        {
            writer.WriteStartObject();

            if (_malformedData is not null)
            {
                writer.WriteString("MalformedData", Convert.ToHexString(_malformedData));
                writer.WriteEndObject();
                return;
            }

            writer.WriteString(nameof(ClientCookie), Convert.ToHexString(_clientCookie));

            if (_serverCookie is not null)
                writer.WriteString(nameof(ServerCookie), Convert.ToHexString(_serverCookie));

            writer.WriteEndObject();
        }

        public override string ToString()
        {
            if (_malformedData is not null)
                return $"COOKIE malformed length={_malformedData.Length}";

            string cookie = $"COOKIE client={Convert.ToHexString(_clientCookie)}";

            return _serverCookie is null ? cookie : $"{cookie} server={Convert.ToHexString(_serverCookie)}";
        }

        #endregion

        #region properties

        public bool IsMalformed => _malformedData is not null;

        public ReadOnlySpan<byte> ClientCookie => _clientCookie;

        public bool HasServerCookie => _serverCookie is not null;

        public ReadOnlySpan<byte> ServerCookie => _serverCookie;

        public override int UncompressedLength => _malformedData?.Length ?? (CLIENT_COOKIE_LENGTH + (_serverCookie?.Length ?? 0));

        #endregion
    }
}
