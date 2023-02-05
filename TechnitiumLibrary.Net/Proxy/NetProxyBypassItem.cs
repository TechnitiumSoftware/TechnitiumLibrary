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
using System.Net;
using System.Net.Sockets;
using TechnitiumLibrary.Net.Dns;

namespace TechnitiumLibrary.Net.Proxy
{
    enum NetProxyBypassItemType
    {
        Unknown = 0,
        IpAddress = 1,
        NetworkAddress = 2,
        DomainName = 3
    }

    public class NetProxyBypassItem
    {
        #region variables

        readonly string _originalValue;

        readonly NetProxyBypassItemType _type;

        readonly IPAddress _ipAddress;
        readonly NetworkAddress _networkAddress;
        readonly string _domainName;

        #endregion

        #region constructor

        public NetProxyBypassItem(string value)
        {
            _originalValue = value;

            if (IPAddress.TryParse(value, out _ipAddress))
            {
                _type = NetProxyBypassItemType.IpAddress;
            }
            else if (NetworkAddress.TryParse(value, out _networkAddress))
            {
                switch (_networkAddress.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        if (_networkAddress.PrefixLength == 32)
                        {
                            _type = NetProxyBypassItemType.IpAddress;
                            _ipAddress = _networkAddress.Address;
                            _networkAddress = null;
                            return;
                        }

                        break;

                    case AddressFamily.InterNetworkV6:
                        if (_networkAddress.PrefixLength == 128)
                        {
                            _type = NetProxyBypassItemType.IpAddress;
                            _ipAddress = _networkAddress.Address;
                            _networkAddress = null;
                            return;
                        }

                        break;
                }

                _type = NetProxyBypassItemType.NetworkAddress;
            }
            else if (DnsClient.IsDomainNameValid(value))
            {
                _type = NetProxyBypassItemType.DomainName;
                _domainName = value;
            }
            else
            {
                throw new NetProxyException("Invalid proxy bypass value: " + value);
            }
        }

        #endregion

        #region public

        public bool IsMatching(EndPoint ep)
        {
            switch (_type)
            {
                case NetProxyBypassItemType.IpAddress:
                    if (ep is IPEndPoint ipep1)
                        return _ipAddress.Equals(ipep1.Address);

                    return false;

                case NetProxyBypassItemType.NetworkAddress:
                    if (ep is IPEndPoint ipep2)
                        return _networkAddress.Contains(ipep2.Address);

                    return false;

                case NetProxyBypassItemType.DomainName:
                    if (ep is DomainEndPoint dep)
                    {
                        string matchDomainName = dep.Address;

                        if (_domainName.Length == matchDomainName.Length)
                            return _domainName.Equals(matchDomainName, StringComparison.OrdinalIgnoreCase);
                        else
                            return matchDomainName.EndsWith("." + _domainName, StringComparison.OrdinalIgnoreCase);
                    }

                    return false;

                default:
                    throw new NotSupportedException("NetProxyBypassItemType not supported.");
            }
        }

        public override string ToString()
        {
            return _originalValue;
        }

        #endregion

        #region variables

        public string Value
        { get { return _originalValue; } }

        #endregion
    }
}
