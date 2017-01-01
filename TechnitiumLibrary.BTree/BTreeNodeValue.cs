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

using System;

namespace TechnitiumLibrary.BTree
{
    public class BTreeNodeValue<T>
    {
        #region variables

        byte[] _key;
        T _value;

        #endregion

        #region constructor

        public BTreeNodeValue(byte[] key, T value)
        {
            _key = key;
            _value = value;
        }

        #endregion

        #region public

        public override string ToString()
        {
            return BitConverter.ToString(_key).Replace("-", "").ToLower() + ": " + _value.ToString();
        }

        #endregion

        #region properties

        public byte[] Key
        { get { return _key; } }

        public T Value
        { get { return _value; } }

        #endregion
    }
}
