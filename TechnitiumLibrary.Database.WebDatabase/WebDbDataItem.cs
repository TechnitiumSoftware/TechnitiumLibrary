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

using System;
using System.Data;
using System.IO;
using System.Text;

namespace TechnitiumLibrary.Database.WebDatabase
{
    public class WebDbDataItem
    {
        #region variables

        SqlDbType _type;
        byte[] _value;

        #endregion

        #region constructor

        public WebDbDataItem(SqlDbType type, object value)
        {
            _type = type;

            if (value == null)
                _value = null;
            else
            {
                switch (type)
                {
                    case SqlDbType.BigInt:
                        _value = BitConverter.GetBytes((long)value);
                        break;

                    case SqlDbType.VarBinary:
                    case SqlDbType.Binary:
                    case SqlDbType.Image:
                        _value = (byte[])value;
                        break;

                    case SqlDbType.Char:
                    case SqlDbType.VarChar:
                    case SqlDbType.Text:
                        _value = Encoding.ASCII.GetBytes(value as string);
                        break;

                    case SqlDbType.DateTime:
                    case SqlDbType.SmallDateTime:
                        _value = BitConverter.GetBytes(((DateTime)value).ToBinary());
                        break;

                    case SqlDbType.Float:
                        _value = BitConverter.GetBytes((double)value);
                        break;

                    case SqlDbType.Int:
                        _value = BitConverter.GetBytes((int)value);
                        break;

                    case SqlDbType.NChar:
                    case SqlDbType.NText:
                    case SqlDbType.NVarChar:
                        _value = Encoding.UTF8.GetBytes(value as string);
                        break;

                    case SqlDbType.Real:
                        _value = BitConverter.GetBytes((float)value);
                        break;

                    case SqlDbType.SmallInt:
                        _value = BitConverter.GetBytes((Int16)value);
                        break;

                    case SqlDbType.TinyInt:
                        _value = new byte[] { (byte)value };
                        break;

                    default:
                        throw new WebDatabaseException("Data type not supported.");
                }
            }
        }

        public WebDbDataItem(Stream s)
        {
            BinaryReader bR = new BinaryReader(s);

            switch (bR.ReadByte()) //version
            {
                case 1:
                    _type = (SqlDbType)bR.ReadByte();

                    int size = bR.ReadInt32();
                    if (size == -1)
                        _value = null;
                    else
                        _value = bR.ReadBytes(size);

                    break;

                default:
                    throw new WebDatabaseException("WebDbDataItem version not supported.");
            }
        }

        #endregion

        #region public

        public void WriteTo(Stream s)
        {
            WriteTo(new BinaryWriter(s));
        }

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)1);
            bW.Write((byte)_type);

            if (_value == null)
            {
                bW.Write(-1);
            }
            else
            {
                bW.Write(_value.Length);
                bW.Write(_value);
            }
        }

        #endregion

        #region properties

        public SqlDbType Type
        { get { return _type; } }

        public object Value
        {
            get
            {
                if (_value == null)
                    return null;

                switch (_type)
                {
                    case SqlDbType.BigInt:
                        return BitConverter.ToInt64(_value, 0);

                    case SqlDbType.VarBinary:
                    case SqlDbType.Binary:
                    case SqlDbType.Image:
                        return _value;

                    case SqlDbType.Char:
                    case SqlDbType.VarChar:
                    case SqlDbType.Text:
                        return Encoding.ASCII.GetString(_value);

                    case SqlDbType.DateTime:
                    case SqlDbType.SmallDateTime:
                        return DateTime.FromBinary(BitConverter.ToInt64(_value, 0));

                    case SqlDbType.Float:
                        return BitConverter.ToDouble(_value, 0);

                    case SqlDbType.Int:
                        return BitConverter.ToInt32(_value, 0);

                    case SqlDbType.NChar:
                    case SqlDbType.NText:
                    case SqlDbType.NVarChar:
                        return Encoding.UTF8.GetString(_value);

                    case SqlDbType.Real:
                        return BitConverter.ToSingle(_value, 0);

                    case SqlDbType.SmallInt:
                        return BitConverter.ToInt16(_value, 0);

                    case SqlDbType.TinyInt:
                        return _value[0];

                    default:
                        throw new WebDatabaseException("Data type not supported.");
                }
            }
        }

        #endregion
    }
}
