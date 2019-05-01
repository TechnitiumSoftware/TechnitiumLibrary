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
using System.Net;
using System.Net.Sockets;
using System.Text;
using TechnitiumLibrary.Net.Dns;

namespace TechnitiumLibrary.Net
{
    public class DomainEndPoint : EndPoint
    {
        #region variables

        string _address;
        int _port;

        #endregion

        #region constructor

        public DomainEndPoint(string address, int port)
        {
            if (address == null)
                throw new ArgumentNullException();

            DnsClient.IsDomainNameValid(address, true);

            if (IPAddress.TryParse(address, out IPAddress ipAddress))
                throw new ArgumentException("Address must be a domain name: " + address);

            _address = address;
            _port = port;
        }

        #endregion

        #region public

        public byte[] GetAddressBytes()
        {
            byte[] buffer = Encoding.ASCII.GetBytes(_address);
            byte[] address = new byte[1 + buffer.Length];

            address[0] = Convert.ToByte(buffer.Length);
            Buffer.BlockCopy(buffer, 0, address, 1, buffer.Length);

            return address;
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            DomainEndPoint other = obj as DomainEndPoint;
            if (other == null)
                return false;

            if (!_address.Equals(other._address, StringComparison.OrdinalIgnoreCase))
                return false;

            if (_port != other._port)
                return false;

            return true;
        }

        public override int GetHashCode()
        {
            return _address.GetHashCode() ^ _port.GetHashCode();
        }

        public override string ToString()
        {
            return _address + ":" + _port;
        }

        #endregion

        #region properties

        public override AddressFamily AddressFamily
        { get { return AddressFamily.Unspecified; } }

        public string Address
        {
            get { return _address; }
            set { _address = value; }
        }

        public int Port
        {
            get { return _port; }
            set { _port = value; }
        }

        #endregion
    }
}
