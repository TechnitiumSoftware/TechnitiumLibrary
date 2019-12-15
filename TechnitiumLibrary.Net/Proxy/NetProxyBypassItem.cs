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
        readonly IPAddress _networkAddress;
        readonly int _networkMaskWidth;
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
            else if (value.Contains("/"))
            {
                string[] network = value.Split(new char[] { '/' }, 2);

                if (IPAddress.TryParse(network[0], out _networkAddress) && int.TryParse(network[1], out _networkMaskWidth))
                {
                    switch (_networkAddress.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                            if (_networkMaskWidth > 32)
                                throw new NetProxyException("Invalid proxy bypass value: " + value);

                            if (_networkMaskWidth == 32)
                            {
                                _type = NetProxyBypassItemType.IpAddress;
                                _ipAddress = _networkAddress;
                            }
                            else
                            {
                                _type = NetProxyBypassItemType.NetworkAddress;
                            }

                            break;

                        case AddressFamily.InterNetworkV6:
                            if (_networkMaskWidth > 128)
                                throw new NetProxyException("Invalid proxy bypass value: " + value);

                            if (_networkMaskWidth == 128)
                            {
                                _type = NetProxyBypassItemType.IpAddress;
                                _ipAddress = _networkAddress;
                            }
                            else
                            {
                                _type = NetProxyBypassItemType.NetworkAddress;
                            }

                            break;

                        default:
                            throw new NotSupportedException("Address family not supported.");
                    }
                }
                else
                {
                    throw new NetProxyException("Invalid proxy bypass value: " + value);
                }
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
                    if (ep is IPEndPoint)
                        return _ipAddress.Equals((ep as IPEndPoint).Address);

                    return false;

                case NetProxyBypassItemType.NetworkAddress:
                    if (ep is IPEndPoint)
                        return _networkAddress.Equals((ep as IPEndPoint).Address.GetNetworkAddress(_networkMaskWidth));

                    return false;

                case NetProxyBypassItemType.DomainName:
                    if (ep is DomainEndPoint)
                    {
                        string domainName = (ep as DomainEndPoint).Address;

                        if (_domainName.Length == domainName.Length)
                            return _domainName.Equals(domainName, StringComparison.OrdinalIgnoreCase);
                        else
                            return ("." + _domainName).EndsWith(domainName, StringComparison.OrdinalIgnoreCase);
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
