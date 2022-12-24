/*
Technitium Library
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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
using System.Text.Json;

namespace TechnitiumLibrary.Net.Dns
{
    public class DnsDatagramMetadata
    {
        #region variables

        readonly NameServerAddress _server;
        readonly DnsTransportProtocol _protocol;
        readonly int _size;
        readonly double _rtt;

        #endregion

        #region constructor

        public DnsDatagramMetadata(NameServerAddress server, DnsTransportProtocol protocol, int size, double rtt)
        {
            _server = server;
            _protocol = protocol;
            _size = size;
            _rtt = rtt;

            if (_rtt < 0.1)
                _rtt = 0.1;
        }

        #endregion

        #region public

        public void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("NameServer", _server?.ToString());
            jsonWriter.WriteString("Protocol", _protocol.ToString());
            jsonWriter.WriteString("DatagramSize", _size + " bytes");
            jsonWriter.WriteString("RoundTripTime", Math.Round(_rtt, 2) + " ms");

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public NameServerAddress NameServer
        { get { return _server; } }

        public DnsTransportProtocol Protocol
        { get { return _protocol; } }

        public int DatagramSize
        { get { return _size; } }

        public double RoundTripTime
        { get { return _rtt; } }

        #endregion
    }
}
