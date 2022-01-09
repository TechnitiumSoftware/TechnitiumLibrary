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
using System.IO;
using System.Runtime.Serialization;

namespace TechnitiumLibrary.Net.Dns.EDnsOptions
{
    public abstract class EDnsOptionData
    {
        #region variables

        protected readonly ushort _length;

        #endregion

        #region constructors

        protected EDnsOptionData()
        { }

        protected EDnsOptionData(Stream s)
        {
            _length = DnsDatagram.ReadUInt16NetworkOrder(s);

            ReadOptionData(s);
        }

        #endregion

        #region protected

        protected abstract void ReadOptionData(Stream s);

        protected abstract void WriteOptionData(Stream s);

        #endregion

        #region public

        public void WriteTo(Stream s)
        {
            long originalPosition = s.Position;

            //write dummy length
            s.Position += 2;

            //write option data
            WriteOptionData(s);

            long finalPosition = s.Position;

            //write actual length
            ushort length = Convert.ToUInt16(finalPosition - originalPosition - 2);
            s.Position = originalPosition;
            DnsDatagram.WriteUInt16NetworkOrder(length, s);

            s.Position = finalPosition;
        }

        public override abstract bool Equals(object obj);

        public override abstract int GetHashCode();

        public override abstract string ToString();

        #endregion

        #region properties

        [IgnoreDataMember]
        public ushort Length
        { get { return _length; } }

        [IgnoreDataMember]
        public abstract ushort UncompressedLength
        { get; }

        #endregion
    }
}
