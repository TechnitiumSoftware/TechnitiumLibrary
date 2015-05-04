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

namespace TechnitiumLibrary.Net.UPnP.Networking
{
    public class PortMappingEntry
    {
        #region variables

        private IPEndPoint _internalEP;
        private bool _enabled;
        private string _description;
        private int _leaseDuration;

        #endregion

        #region constructor

        public PortMappingEntry(int internalPort, IPAddress internalClient, bool enabled, string description, int leaseDuration)
        {
            _internalEP = new IPEndPoint(internalClient, internalPort);
            _enabled = enabled;
            _description = description;
            _leaseDuration = leaseDuration;
        }

        #endregion

        #region properties

        public IPEndPoint InternalEP
        { get { return _internalEP; } }

        public bool Enabled
        { get { return _enabled; } }

        public string Description
        { get { return _description; } }

        public int LeaseDuration
        { get { return _leaseDuration; } }

        #endregion
    }
}
