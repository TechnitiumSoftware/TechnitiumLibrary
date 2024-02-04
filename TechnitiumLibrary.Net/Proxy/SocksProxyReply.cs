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

using System.IO;
using System.Net;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.Proxy
{
    public enum SocksProxyReplyCode : byte
    {
        Succeeded = 0x00,
        GeneralSocksServerFailure = 0x01,
        ConnectionNotAllowedByRuleset = 0x02,
        NetworkUnreachable = 0x03,
        HostUnreachable = 0x04,
        ConnectionRefused = 0x05,
        TtlExpired = 0x06,
        CommandNotSupported = 0x07,
        AddressTypeNotSupported = 0x08
    }

    class SocksProxyReply
    {
        #region variables

        const byte SOCKS_VERSION = 5;

        byte _version;
        SocksProxyReplyCode _reply;
        EndPoint _bindEP;

        #endregion

        #region constructors

        private SocksProxyReply()
        { }

        public SocksProxyReply(SocksProxyReplyCode reply)
            : this(reply, new IPEndPoint(IPAddress.Any, 0))
        { }

        public SocksProxyReply(SocksProxyReplyCode reply, EndPoint bindEP)
        {
            _version = SOCKS_VERSION;
            _reply = reply;
            _bindEP = bindEP;
        }

        #endregion

        #region static

        public static async Task<SocksProxyReply> ReadReplyAsync(Stream s)
        {
            SocksProxyReply reply = new SocksProxyReply();

            byte[] buffer = new byte[3];

            await s.ReadExactlyAsync(buffer);

            reply._version = buffer[0];
            reply._reply = (SocksProxyReplyCode)buffer[1];
            reply._bindEP = await SocksProxyServer.ReadEndPointAsync(s);

            return reply;
        }

        #endregion

        #region public

        public async Task WriteToAsync(Stream s)
        {
            byte[] buffer = new byte[3];

            buffer[0] = _version;
            buffer[1] = (byte)_reply;

            await s.WriteAsync(buffer, 0, 3);
            await SocksProxyServer.WriteEndPointAsync(_bindEP, s);
        }

        #endregion

        #region properties

        public byte Version
        { get { return _version; } }

        public bool IsVersionSupported
        { get { return _version == SOCKS_VERSION; } }

        public SocksProxyReplyCode ReplyCode
        { get { return _reply; } }

        public EndPoint BindEndPoint
        { get { return _bindEP; } }

        #endregion
    }
}
