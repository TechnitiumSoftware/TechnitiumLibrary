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
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace TechnitiumLibrary.Net.BitTorrent
{
    public enum BencodingType
    {
        String = 0,
        Integer = 1,
        List = 2,
        Dictionary = 3
    }

    public class Bencoding
    {
        #region variables

        BencodingType _type;
        object _value;

        #endregion

        #region constructor

        public Bencoding(BencodingType type, object value)
        {
            _type = type;
            _value = value;
        }

        #endregion

        #region static

        private static void EncodeInteger(long value, Stream s)
        {
            byte[] buffer = Encoding.ASCII.GetBytes("i" + value + "e");
            s.Write(buffer, 0, buffer.Length);
        }

        private static long DecodeInteger(Stream s)
        {
            string TMP = string.Empty;
            int b;

            while (true)
            {
                b = s.ReadByte();

                switch (b)
                {
                    case 101: //e
                        return Convert.ToInt64(TMP);

                    case -1:
                        throw new EndOfStreamException();
                }

                TMP += Convert.ToChar(b);
            }
        }

        private static void EncodeString(byte[] value, Stream s)
        {
            byte[] buffer = Encoding.ASCII.GetBytes(value.Length + ":");
            s.Write(buffer, 0, buffer.Length);
            s.Write(value, 0, value.Length);
        }

        private static byte[] DecodeString(Stream s, byte preByte)
        {
            string TMP = string.Empty;

            while (true)
            {
                if (preByte == 58) //:
                    break;

                TMP += Convert.ToChar(preByte);
                preByte = Convert.ToByte(s.ReadByte());
            }

            byte[] buffer = new byte[Convert.ToInt32(TMP)];

            if (s.Read(buffer, 0, buffer.Length) == buffer.Length)
                return buffer;

            throw new Exception("Invalid bencoded string format.");
        }

        private static void EncodeList(List<Bencoding> list, Stream s)
        {
            s.WriteByte(108); //l

            foreach (Bencoding item in list)
                item.Encode(s);

            s.WriteByte(101); //e
        }

        private static List<Bencoding> DecodeList(Stream s)
        {
            List<Bencoding> list = new List<Bencoding>();

            while (true)
            {
                Bencoding b = Bencoding.Decode(s);

                if (b == null)
                    break;

                list.Add(b);
            }

            return list;
        }

        private static void EncodeDictionary(Dictionary<string, Bencoding> dict, Stream s)
        {
            s.WriteByte(100); //d

            foreach (KeyValuePair<string, Bencoding> item in dict)
            {
                EncodeString(Encoding.ASCII.GetBytes(item.Key), s);
                item.Value.Encode(s);
            }

            s.WriteByte(101); //e
        }

        private static Dictionary<string, Bencoding> DecodeDictionary(Stream s)
        {
            Dictionary<string, Bencoding> dict = new Dictionary<string, Bencoding>();

            while (true)
            {
                Bencoding b = Bencoding.Decode(s);

                if (b == null)
                    break;

                if (b.Type != BencodingType.String)
                    throw new Exception("Invalid bencoded dictionary format.");

                dict.Add(b.ValueString, Decode(s));
            }

            return dict;
        }

        public static Bencoding Decode(Stream s)
        {
            int b = s.ReadByte();

            switch (b)
            {
                case -1:
                    throw new EndOfStreamException();

                case 105: //i = integer
                    return new Bencoding(BencodingType.Integer, DecodeInteger(s));

                case 108: //l = list
                    return new Bencoding(BencodingType.List, DecodeList(s));

                case 100: //d = dictionary
                    return new Bencoding(BencodingType.Dictionary, DecodeDictionary(s));

                case 101: //e = end
                    return null;

                default: //string
                    return new Bencoding(BencodingType.String, DecodeString(s, Convert.ToByte(b)));
            }
        }

        public static Bencoding Decode(byte[] data)
        {
            using (MemoryStream mS = new MemoryStream(data))
            {
                return Decode(mS);
            }
        }

        #endregion

        #region public

        public void Encode(Stream stream)
        {
            switch (_type)
            {
                case BencodingType.Integer:
                    EncodeInteger((long)_value, stream);
                    break;

                case BencodingType.String:
                    if (_value.GetType().Equals(typeof(string)))
                        EncodeString(Encoding.ASCII.GetBytes(_value as string), stream);
                    else
                        EncodeString((_value as byte[]), stream);
                    break;

                case BencodingType.List:
                    EncodeList((_value as List<Bencoding>), stream);
                    break;

                case BencodingType.Dictionary:
                    EncodeDictionary((_value as Dictionary<string, Bencoding>), stream);
                    break;

                default:
                    throw new Exception("Invalid bencoded value type.");
            }
        }

        #endregion

        #region properties

        public BencodingType Type
        {
            get { return _type; }
        }

        public object Value
        {
            get { return _value; }
        }

        public string ValueString
        {
            get { return Encoding.ASCII.GetString(_value as byte[]); }
        }

        public long ValueInteger
        {
            get { return (long)_value; }
        }

        public List<Bencoding> ValueList
        {
            get { return (_value as List<Bencoding>); }
        }

        public Dictionary<string, Bencoding> ValueDictionary
        {
            get { return (_value as Dictionary<string, Bencoding>); }
        }

        #endregion
    }
}
