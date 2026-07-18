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
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

namespace TechnitiumLibrary.Net
{
    public class InterfaceEndPoint : IPEndPoint
    {
        #region variables

        string _interfaceName;

        #endregion

        #region constructor

        public InterfaceEndPoint(IPAddress address, int port, string interfaceName = null)
            : base(address, port)
        {
            InterfaceName = interfaceName;
        }

        #endregion

        #region static

        public new static InterfaceEndPoint Parse(string value)
        {
            if (TryParse(value, out InterfaceEndPoint intEP))
                return intEP;

            throw new FormatException("Failed to parse interface end point: " + value);
        }

        public static bool TryParse(string value, out InterfaceEndPoint intEP)
        {
            //fe80::3a3a:12c9:15f4:3355
            //192.168.10.2%eth0:53
            //[fe80::3a3a:12c9:15f4:3355%eth1]:53
            //[fe80::3a3a:12c9:15f4:3355%11]:53

            string interfaceString;
            string ipString;
            string portString;

            int i = value.LastIndexOf(':');
            if (i < 0)
            {
                ipString = value;
                portString = null;
            }
            else
            {
                int i1 = value.IndexOf(':');
                if ((i1 == i) || (value[i - 1] == ']'))
                {
                    //only one collon or [ipv6] case; so port exist
                    ipString = value.Substring(0, i);
                    portString = value.Substring(i + 1);
                }
                else
                {
                    ipString = value;
                    portString = null;
                }
            }

            if (ipString.StartsWith('['))
            {
                if (!ipString.EndsWith(']'))
                {
                    intEP = null;
                    return false;
                }

                ipString = ipString.Substring(1, ipString.Length - 2);
            }

            int j = ipString.LastIndexOf('%');
            if (j < 0)
            {
                interfaceString = null;
            }
            else
            {
                interfaceString = ipString.Substring(j + 1);
                ipString = ipString.Substring(0, j);
            }

            if (!IPAddress.TryParse(ipString, out IPAddress ipAddress))
            {
                intEP = null;
                return false;
            }

            if (!int.TryParse(portString, out int port))
                port = 0;

            intEP = new InterfaceEndPoint(ipAddress, port, interfaceString);
            return true;
        }

        #endregion

        #region public

        public override bool Equals([NotNullWhen(true)] object comparand)
        {
            if (comparand is null)
                return false;

            if (ReferenceEquals(this, comparand))
                return true;

            if (comparand is InterfaceEndPoint other)
            {
                if ((_interfaceName is null) && (other._interfaceName is null))
                {
                    //consider equal
                }
                else if (_interfaceName != other._interfaceName)
                {
                    return false;
                }
            }

            return base.Equals(comparand);
        }

        public override int GetHashCode()
        {
            return base.GetHashCode() ^ HashCode.Combine(_interfaceName);
        }

        public override string ToString()
        {
            if (_interfaceName is null)
                return base.ToString();

            switch (AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    return Address.ToString() + "%" + _interfaceName + ":" + Port.ToString();

                case AddressFamily.InterNetworkV6:
                    return "[" + Address.ToString() + "%" + _interfaceName + "]:" + Port.ToString();

                default:
                    return base.ToString();
            }
        }

        #endregion

        #region properties

        public string InterfaceName
        {
            get { return _interfaceName; }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    _interfaceName = null;
                }
                else
                {
                    if ((Address.AddressFamily == AddressFamily.InterNetworkV6) && int.TryParse(value, out int scopeId))
                        Address.ScopeId = scopeId;
                    else
                        _interfaceName = value;
                }
            }
        }

        #endregion
    }
}
