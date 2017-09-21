/*
Technitium Library
Copyright (C) 2017  Shreyas Zare (shreyas@technitium.com)

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

namespace TechnitiumLibrary.Net.Dns
{
    public class DnsDomainOffset
    {
        #region variables

        ushort _offset;
        string _domain;

        #endregion

        #region constructor

        public DnsDomainOffset(ushort offset, string domain)
        {
            _offset = offset;
            _domain = domain;
        }

        #endregion

        #region public

        public override string ToString()
        {
            return _domain;
        }

        #endregion

        #region properties

        public ushort Offset
        { get { return _offset; } }

        public string Domain
        { get { return _domain; } }

        #endregion
    }
}
