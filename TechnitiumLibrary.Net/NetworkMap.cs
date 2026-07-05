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
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace TechnitiumLibrary.Net
{
    public class NetworkMap<T>
    {
        #region variables

        readonly AddressFamily _addressFamily;
        readonly List<IpEntry> _ipLookupList;
        bool _sorted;

        #endregion

        #region constructor

        public NetworkMap(AddressFamily addressFamily)
        {
            _addressFamily = addressFamily;
            _ipLookupList = new List<IpEntry>();
        }

        public NetworkMap(AddressFamily addressFamily, int capacity)
        {
            _addressFamily = addressFamily;
            _ipLookupList = new List<IpEntry>(capacity);
        }

        #endregion

        #region private

        private IpEntry GetFloorEntry(IpEntry entry)
        {
            int i = _ipLookupList.BinarySearch(entry);
            if (i >= 0)
            {
                //item found
                return _ipLookupList[i];
            }
            else
            {
                //item not found
                int iHigh = ~i; //bitwise compliment of return value

                if (iHigh == _ipLookupList.Count)
                    return null; //bigger than all items
                else if (iHigh == 0)
                    return null; //smaller than all items
                else
                    return _ipLookupList[iHigh - 1]; //between 2 items; return lower item
            }
        }

        private IpEntry GetCeilingEntry(IpEntry entry)
        {
            int i = _ipLookupList.BinarySearch(entry);
            if (i >= 0)
            {
                //item found
                return _ipLookupList[i];
            }
            else
            {
                //item not found
                int iHigh = ~i; //bitwise compliment of return value

                if (iHigh == _ipLookupList.Count)
                    return null; //bigger than all items
                else if (iHigh == 0)
                    return null; //smaller than all items
                else
                    return _ipLookupList[iHigh]; //between 2 items; return higher item
            }
        }

        #endregion

        #region public

        public void Add(string networkAddress, T value)
        {
            Add(NetworkAddress.Parse(networkAddress), value);
        }

        public void Add(NetworkAddress networkAddress, T value)
        {
            if (networkAddress.AddressFamily != _addressFamily)
                throw new ArgumentException("The address family must be '" + _addressFamily.ToString() + "'.", nameof(networkAddress));

            lock (_ipLookupList)
            {
                _ipLookupList.Add(new IpEntry(networkAddress.Address, value));
                _ipLookupList.Add(new IpEntry(networkAddress.GetLastAddress(), value));

                _sorted = false;
            }
        }

        public bool Remove(string networkAddress)
        {
            return Remove(NetworkAddress.Parse(networkAddress));
        }

        public bool Remove(NetworkAddress networkAddress)
        {
            if (networkAddress.AddressFamily != _addressFamily)
                throw new ArgumentException("The address family must be '" + _addressFamily.ToString() + "'.", nameof(networkAddress));

            lock (_ipLookupList)
            {
                bool v1 = _ipLookupList.Remove(new IpEntry(networkAddress.Address));
                bool v2 = _ipLookupList.Remove(new IpEntry(networkAddress.GetLastAddress()));

                _sorted = false;
                return v1 & v2;
            }
        }

        public bool TryGetValue(string address, out T value)
        {
            return TryGetValue(IPAddress.Parse(address), out value);
        }

        public bool TryGetValue(IPAddress address, out T value)
        {
            if (address.AddressFamily != _addressFamily)
                throw new ArgumentException("The address family must be '" + _addressFamily.ToString() + "'.", nameof(address));

            if (!_sorted)
            {
                lock (_ipLookupList)
                {
                    if (!_sorted)
                    {
                        _ipLookupList.Sort();
                        _sorted = true;
                    }
                }
            }

            IpEntry findEntry = new IpEntry(address);

            IpEntry floorEntry = GetFloorEntry(findEntry);
            IpEntry ceilingEntry = GetCeilingEntry(findEntry);

            if ((floorEntry == null) || (ceilingEntry == null))
            {
                value = default;
                return false;
            }

            if (floorEntry.IpAddress.SequenceEqual(findEntry.IpAddress))
                value = floorEntry.Value;
            else if (ceilingEntry.IpAddress.SequenceEqual(findEntry.IpAddress))
                value = ceilingEntry.Value;
            else if (ReferenceEquals(floorEntry.Value, ceilingEntry.Value))
                value = floorEntry.Value;
            else
            {
                value = default;
                return false;
            }

            return true;
        }

        #endregion

        class IpEntry : IComparable<IpEntry>
        {
            #region variables

            readonly byte[] _ipAddress;
            readonly T _value;

            #endregion

            #region constructor

            public IpEntry(IPAddress ipAddress, T value)
            {
                _ipAddress = ipAddress.GetAddressBytes();
                _value = value;
            }

            public IpEntry(IPAddress ipAddress)
            {
                _ipAddress = ipAddress.GetAddressBytes();
            }

            #endregion

            #region private

            public static bool LessThan(byte[] b1, byte[] b2)
            {
                if (b1.Length != b2.Length)
                    throw new ArgumentException("Operand value length not equal.");

                for (int i = 0; i < b1.Length; i++)
                {
                    if (b1[i] < b2[i])
                        return true;

                    if (b1[i] > b2[i])
                        return false;
                }

                return false;
            }

            public static bool GreaterThan(byte[] b1, byte[] b2)
            {
                if (b1.Length != b2.Length)
                    throw new ArgumentException("Operand value length not equal.");

                for (int i = 0; i < b1.Length; i++)
                {
                    if (b1[i] > b2[i])
                        return true;

                    if (b1[i] < b2[i])
                        return false;
                }

                return false;
            }

            #endregion

            #region public

            public int CompareTo(IpEntry other)
            {
                if (LessThan(_ipAddress, other._ipAddress))
                    return -1;
                else if (GreaterThan(_ipAddress, other._ipAddress))
                    return 1;
                else
                    return 0;
            }

            public override bool Equals(object obj)
            {
                if (obj is null)
                    return false;

                if (ReferenceEquals(this, obj))
                    return true;

                if (obj is IpEntry other)
                    return _ipAddress.Equals(other._ipAddress);

                return false;
            }

            public override int GetHashCode()
            {
                return HashCode.Combine(_ipAddress);
            }

            #endregion

            #region properties

            public byte[] IpAddress
            { get { return _ipAddress; } }

            public T Value
            { get { return _value; } }

            #endregion
        }
    }
}
