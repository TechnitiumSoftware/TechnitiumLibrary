/*
Technitium Library
Copyright (C) 2020  Shreyas Zare (shreyas@technitium.com)

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
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Proxy
{
    enum SocksProxyRequestCommand : byte
    {
        Connect = 0x01,
        Bind = 0x02,
        UdpAssociate = 0x03
    }

    class SocksProxyRequest
    {
        #region variables

        const byte SOCKS_VERSION = 5;

        byte _version;
        SocksProxyRequestCommand _command;
        EndPoint _dstEP;

        #endregion

        #region constructors

        private SocksProxyRequest()
        { }

        public SocksProxyRequest(SocksProxyRequestCommand command, EndPoint dstEP)
        {
            _version = SOCKS_VERSION;
            _command = command;
            _dstEP = dstEP;
        }

        #endregion

        #region static

        public static async Task<SocksProxyRequest> ReadRequestAsync(Stream s)
        {
            SocksProxyRequest request = new SocksProxyRequest();

            byte[] buffer = new byte[3];
            await s.ReadBytesAsync(buffer, 0, 3);

            request._version = buffer[0];
            request._command = (SocksProxyRequestCommand)buffer[1];
            request._dstEP = await SocksProxyServer.ReadEndPointAsync(s);

            return request;
        }

        #endregion

        #region public

        public async Task WriteToAsync(Stream s)
        {
            byte[] buffer = new byte[3];

            buffer[0] = _version;
            buffer[1] = (byte)_command;

            await s.WriteAsync(buffer, 0, 3);
            await SocksProxyServer.WriteEndPointAsync(_dstEP, s);
        }

        #endregion

        #region properties

        public byte Version
        { get { return _version; } }

        public bool IsVersionSupported
        { get { return _version == SOCKS_VERSION; } }

        public SocksProxyRequestCommand Command
        { get { return _command; } }

        public EndPoint DestinationEndPoint
        { get { return _dstEP; } }

        #endregion
    }
}
