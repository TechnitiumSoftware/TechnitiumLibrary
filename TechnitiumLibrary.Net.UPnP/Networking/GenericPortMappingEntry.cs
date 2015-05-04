/*
Technitium Library
Copyright (C) 2015  Shreyas Zare (shreyas@technitium.com)

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

using System.Net;
using System.Net.Sockets;

namespace TechnitiumLibrary.Net.UPnP.Networking
{
    public class GenericPortMappingEntry : PortMappingEntry
    {
        #region variables

        private IPEndPoint _externalEP;
        private ProtocolType _protocol;

        #endregion

        #region constructor

        public GenericPortMappingEntry(IPAddress remoteHost, int externalPort, ProtocolType protocol, int internalPort, IPAddress internalClient, bool enabled, string description, int leaseDuration)
            : base(internalPort, internalClient, enabled, description, leaseDuration)
        {
            _externalEP = new IPEndPoint(remoteHost, externalPort);
            _protocol = protocol;
        }

        #endregion

        #region properties

        public IPEndPoint ExternalEP
        {
            get { return _externalEP; }
        }

        public ProtocolType Protocol
        {
            get { return _protocol; }
        }

        #endregion
    }
}