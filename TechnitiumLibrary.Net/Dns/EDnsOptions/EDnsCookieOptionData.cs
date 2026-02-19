/*
Technitium Library
Copyright(C) 2026  Shreyas Zare(shreyas @technitium.com)

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
        byte[] _serverCookie; // null means absent (client-cookie-only) 

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
            // _length is OPTION-LENGTH (bytes of option data).
            if (_length < CLIENT_COOKIE_LENGTH)
                throw new InvalidDataException($"Invalid COOKIE option length: {_length} bytes");

            int serverLen = _length - CLIENT_COOKIE_LENGTH;

            // Valid serverLen: 0 OR 8..32.
            if (serverLen != 0 && (serverLen < SERVER_COOKIE_MIN_LENGTH || serverLen > SERVER_COOKIE_MAX_LENGTH))
                throw new InvalidDataException($"Invalid server cookie length: {serverLen} bytes. Valid lengths are exactly 0 bytes, or between {SERVER_COOKIE_MIN_LENGTH} and {SERVER_COOKIE_MAX_LENGTH} bytes.");

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

            if (!_clientCookie.AsSpan().SequenceEqual(other._clientCookie))
                return false;

            if (_serverCookie is null && other._serverCookie is null)
                return true;

            if (_serverCookie is null || other._serverCookie is null)
                return false;

            return _serverCookie.AsSpan().SequenceEqual(other._serverCookie);
        }

        public override bool Equals(object obj) => Equals(obj as EDnsCookieOptionData);

        public override int GetHashCode()
        {
            HashCode hash = new();

            foreach (byte b in _clientCookie)
                hash.Add(b);

            if (_serverCookie is not null)
                foreach (byte b in _serverCookie)
                    hash.Add(b);

            return hash.ToHashCode();
        }

        public override void SerializeTo(Utf8JsonWriter writer)
        {
            writer.WriteStartObject();

            writer.WriteString("ClientCookie", Convert.ToHexString(_clientCookie));

            if (_serverCookie is not null)
                writer.WriteString("ServerCookie", Convert.ToHexString(_serverCookie));

            writer.WriteEndObject();
        }

        public override string ToString()
        {
            if (_serverCookie is null)
                return $"COOKIE client={Convert.ToHexString(_clientCookie)}";

            return $"COOKIE client={Convert.ToHexString(_clientCookie)} server={Convert.ToHexString(_serverCookie)}";
        }

        #endregion

        #region properties
        public ReadOnlySpan<byte> ClientCookie => _clientCookie;
        public bool HasServerCookie => _serverCookie is not null;
        public ReadOnlySpan<byte> ServerCookie => _serverCookie is null ? ReadOnlySpan<byte>.Empty : _serverCookie;
        public override int UncompressedLength => CLIENT_COOKIE_LENGTH + (_serverCookie?.Length ?? 0);

        #endregion
    }
}