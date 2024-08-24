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

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net
{
    public class NetworkAccessControl : IEquatable<NetworkAccessControl>
    {
        #region variables

        readonly static char[] _parserTrimStartChars = ['!', ' ', '\t'];

        readonly bool _deny;
        readonly NetworkAddress _networkAddress;

        #endregion

        #region constructor

        public NetworkAccessControl(NetworkAddress networkAddress, bool deny = false)
        {
            _deny = deny;
            _networkAddress = networkAddress;
        }

        public NetworkAccessControl(IPAddress address, byte prefixLength, bool deny = false)
            : this(new NetworkAddress(address, prefixLength), deny)
        { }

        #endregion

        #region static

        public static NetworkAccessControl Parse(string value)
        {
            if (TryParse(value, out NetworkAccessControl networkAccessControl))
                return networkAccessControl;

            throw new FormatException("Invalid Network Access Control value was specified: " + value);
        }

        public static bool TryParse(string value, out NetworkAccessControl networkAccessControl)
        {
            bool deny = value.StartsWith('!');

            if (NetworkAddress.TryParse(deny ? value.TrimStart(_parserTrimStartChars) : value, out NetworkAddress networkAddress))
            {
                networkAccessControl = new NetworkAccessControl(networkAddress, deny);
                return true;
            }

            networkAccessControl = null;
            return false;
        }

        public static NetworkAccessControl ReadFrom(BinaryReader bR)
        {
            return ReadFrom(bR.BaseStream);
        }

        public static NetworkAccessControl ReadFrom(Stream s)
        {
            bool deny = s.ReadByteValue() != 0;
            NetworkAddress networkAddress = NetworkAddress.ReadFrom(s);

            return new NetworkAccessControl(networkAddress, deny);
        }

        public static bool IsAddressAllowed(IPAddress address, IReadOnlyCollection<NetworkAccessControl> acl, bool allowLoopbackWhenNoMatch = false)
        {
            if (acl is not null)
            {
                foreach (NetworkAccessControl nac in acl)
                {
                    if (nac.TryMatch(address, out bool isAllowed))
                        return isAllowed;
                }
            }

            if (allowLoopbackWhenNoMatch && IPAddress.IsLoopback(address))
                return true;

            return false;
        }

        public static DnsAPLRecordData ConvertToAPLRecordData(IReadOnlyCollection<NetworkAccessControl> acl)
        {
            DnsAPLRecordData.APItem[] apItems = new DnsAPLRecordData.APItem[acl.Count];
            int i = 0;

            foreach (NetworkAccessControl ac in acl)
                apItems[i++] = new DnsAPLRecordData.APItem(ac._networkAddress, ac._deny);

            return new DnsAPLRecordData(apItems);
        }

        public static IReadOnlyCollection<NetworkAccessControl> ConvertFromAPLRecordData(DnsAPLRecordData rdata)
        {
            IReadOnlyCollection<DnsAPLRecordData.APItem> apItems = rdata.APItems;
            NetworkAccessControl[] acl = new NetworkAccessControl[apItems.Count];
            int i = 0;

            foreach (DnsAPLRecordData.APItem apItem in apItems)
                acl[i++] = new NetworkAccessControl(apItem.NetworkAddress, apItem.Negation);

            return acl;
        }

        #endregion

        #region public

        public bool TryMatch(IPAddress address, out bool isAllowed)
        {
            if (_networkAddress.Contains(address))
            {
                isAllowed = !_deny;
                return true;
            }

            isAllowed = false;
            return false;
        }

        public void WriteTo(BinaryWriter bW)
        {
            WriteTo(bW.BaseStream);
        }

        public void WriteTo(Stream s)
        {
            if (_deny)
                s.WriteByte(1);
            else
                s.WriteByte(0);

            _networkAddress.WriteTo(s);
        }

        public bool Equals(NetworkAccessControl other)
        {
            if (other is null)
                return false;

            if (ReferenceEquals(this, other))
                return true;

            if (_deny != other._deny)
                return false;

            return _networkAddress.Equals(other._networkAddress);
        }

        public override bool Equals(object obj)
        {
            if (obj is NetworkAccessControl other)
                return Equals(other);

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_deny, _networkAddress);
        }

        public override string ToString()
        {
            return (_deny ? "!" : "") + _networkAddress.ToString();
        }

        #endregion

        #region properties

        public bool Deny
        { get { return _deny; } }

        public NetworkAddress NetworkAddress
        { get { return _networkAddress; } }

        #endregion
    }
}
