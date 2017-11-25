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
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace TechnitiumLibrary.IO
{
    public enum BincodingType : byte
    {
        NULL = 0,
        BOOLEAN = 1,
        BYTE = 2,
        SHORT = 3,
        INTEGER = 4,
        LONG = 5,
        USHORT = 6,
        UINTEGER = 7,
        ULONG = 8,
        BINARY = 9,
        STRING = 10,
        STREAM = 11,
        LIST = 12,
        KEY_VALUE_PAIR = 13,
        DICTIONARY = 14,
        DATETIME = 15
    }

    public class Bincoding
    {
        #region variables

        static readonly DateTime _epoch = new DateTime(1970, 1, 1);

        BincodingType _type;
        byte[] _value;
        Stream _stream;
        List<Bincoding> _list;
        KeyValuePair<string, Bincoding> _keyValue;
        Dictionary<string, Bincoding> _dictionary;

        #endregion

        #region constructor

        public Bincoding(BincodingType type, byte[] value)
        {
            _type = type;
            _value = value;
        }

        private Bincoding(Stream value)
        {
            _type = BincodingType.STREAM;
            _stream = value;
        }

        private Bincoding(List<Bincoding> value)
        {
            _type = BincodingType.LIST;
            _list = value;
        }

        private Bincoding(KeyValuePair<string, Bincoding> value)
        {
            _type = BincodingType.KEY_VALUE_PAIR;
            _keyValue = value;
        }

        private Bincoding(Dictionary<string, Bincoding> value)
        {
            _type = BincodingType.DICTIONARY;
            _dictionary = value;
        }

        #endregion

        #region static

        public static Bincoding GetNullValue()
        {
            return new Bincoding(BincodingType.NULL, null);
        }

        public static Bincoding GetValue(bool value)
        {
            return new Bincoding(BincodingType.BOOLEAN, BitConverter.GetBytes(value));
        }

        public static Bincoding GetValue(byte value)
        {
            return new Bincoding(BincodingType.BYTE, new byte[] { value });
        }

        public static Bincoding GetValue(short value)
        {
            return new Bincoding(BincodingType.SHORT, BitConverter.GetBytes(value));
        }

        public static Bincoding GetValue(int value)
        {
            return new Bincoding(BincodingType.INTEGER, BitConverter.GetBytes(value));
        }

        public static Bincoding GetValue(long value)
        {
            return new Bincoding(BincodingType.LONG, BitConverter.GetBytes(value));
        }

        public static Bincoding GetValue(ushort value)
        {
            return new Bincoding(BincodingType.USHORT, BitConverter.GetBytes(value));
        }

        public static Bincoding GetValue(uint value)
        {
            return new Bincoding(BincodingType.UINTEGER, BitConverter.GetBytes(value));
        }

        public static Bincoding GetValue(ulong value)
        {
            return new Bincoding(BincodingType.ULONG, BitConverter.GetBytes(value));
        }

        public static Bincoding GetValue(DateTime value)
        {
            return new Bincoding(BincodingType.DATETIME, BitConverter.GetBytes(Convert.ToInt64((value - _epoch).TotalMilliseconds)));
        }

        public static Bincoding GetValue(byte[] value)
        {
            return new Bincoding(BincodingType.BINARY, value);
        }

        public static Bincoding GetValue(IWriteStream value)
        {
            using (MemoryStream mS = new MemoryStream())
            {
                value.WriteTo(mS);

                return new Bincoding(BincodingType.BINARY, mS.ToArray());
            }
        }

        public static Bincoding GetValue(string value)
        {
            return new Bincoding(BincodingType.STRING, Encoding.UTF8.GetBytes(value));
        }

        public static Bincoding GetValue(Stream value)
        {
            return new Bincoding(BincodingType.STREAM, null) { _stream = value };
        }

        public static Bincoding GetValue(List<Bincoding> value)
        {
            return new Bincoding(value);
        }

        public static Bincoding GetValue(IWriteStream[] value)
        {
            List<Bincoding> value2 = new List<Bincoding>(value.Length);

            foreach (IWriteStream item in value)
                value2.Add(Bincoding.GetValue(item));

            return new Bincoding(value2);
        }

        public static Bincoding GetValue(KeyValuePair<string, Bincoding> value)
        {
            return new Bincoding(value);
        }

        public static Bincoding GetValue(string key, Bincoding value)
        {
            return new Bincoding(new KeyValuePair<string, Bincoding>(key, value));
        }

        public static Bincoding GetValue(Dictionary<string, Bincoding> value)
        {
            return new Bincoding(value);
        }

        #endregion

        #region public

        public Stream GetValueStream()
        {
            if (_type == BincodingType.STREAM)
                return _stream;
            else
                return new MemoryStream(_value, false);
        }

        public bool GetBooleanValue()
        {
            return BitConverter.ToBoolean(_value, 0);
        }

        public byte GetByteValue()
        {
            return _value[0];
        }

        public short GetShortValue()
        {
            return BitConverter.ToInt16(_value, 0);
        }

        public int GetIntegerValue()
        {
            return BitConverter.ToInt32(_value, 0);
        }

        public long GetLongValue()
        {
            return BitConverter.ToInt64(_value, 0);
        }

        public ushort GetUShortValue()
        {
            return BitConverter.ToUInt16(_value, 0);
        }

        public uint GetUIntegerValue()
        {
            return BitConverter.ToUInt32(_value, 0);
        }

        public ulong GetULongValue()
        {
            return BitConverter.ToUInt64(_value, 0);
        }

        public DateTime GetDateTimeValue()
        {
            return _epoch.AddMilliseconds(BitConverter.ToInt64(_value, 0));
        }

        public string GetStringValue()
        {
            return Encoding.UTF8.GetString(_value);
        }

        public List<Bincoding> GetList()
        {
            return _list;
        }

        public KeyValuePair<string, Bincoding> GetKeyValuePair()
        {
            return _keyValue;
        }

        public Dictionary<string, Bincoding> GetDictionary()
        {
            return _dictionary;
        }

        #endregion

        #region properties

        public BincodingType Type
        { get { return _type; } }

        public byte[] Value
        { get { return _value; } }

        #endregion
    }

    public class BincodingEncoder
    {
        #region variables

        Stream _s;

        string _format;
        byte _version;

        #endregion

        #region constructor

        public BincodingEncoder(Stream s)
        {
            _s = s;
        }

        public BincodingEncoder(Stream s, string format, byte version)
        {
            if (format.Length != 2)
                throw new ArgumentException("Argument 'format' must be of 2 characters.");

            s.Write(Encoding.ASCII.GetBytes(format), 0, 2);
            s.WriteByte(version);

            _s = s;
            _format = format;
            _version = version;
        }

        #endregion

        #region private

        private void WriteLength(Stream s, int valueLength)
        {
            if (valueLength < 128)
            {
                s.WriteByte((byte)valueLength);
            }
            else
            {
                byte[] bytesValueLength = BitConverter.GetBytes(valueLength);
                Array.Reverse(bytesValueLength);

                for (int i = 0; i < bytesValueLength.Length; i++)
                {
                    if (bytesValueLength[i] != 0)
                    {
                        s.WriteByte((byte)(0x80 | (bytesValueLength.Length - i)));
                        s.Write(bytesValueLength, i, bytesValueLength.Length - i);
                        break;
                    }
                }
            }
        }

        #endregion

        #region public

        public void Encode(Bincoding value)
        {
            _s.WriteByte((byte)value.Type);

            switch (value.Type)
            {
                case BincodingType.NULL:
                    break;

                case BincodingType.BINARY:
                case BincodingType.STRING:
                    WriteLength(_s, value.Value.Length);
                    _s.Write(value.Value, 0, value.Value.Length);
                    break;

                case BincodingType.STREAM:
                    Stream stream = value.GetValueStream();

                    WriteLength(_s, Convert.ToInt32(stream.Length - stream.Position));
                    OffsetStream.StreamCopy(stream, _s);
                    break;

                case BincodingType.LIST:
                    List<Bincoding> list = value.GetList();

                    WriteLength(_s, list.Count);

                    foreach (Bincoding item in list)
                        Encode(item);

                    break;

                case BincodingType.KEY_VALUE_PAIR:
                    KeyValuePair<string, Bincoding> keyValue = value.GetKeyValuePair();

                    byte[] keyBuffer = Encoding.UTF8.GetBytes(keyValue.Key);
                    _s.WriteByte(Convert.ToByte(keyBuffer.Length));
                    _s.Write(keyBuffer, 0, keyBuffer.Length);

                    Encode(keyValue.Value);

                    break;

                case BincodingType.DICTIONARY:
                    Dictionary<string, Bincoding> dictionary = value.GetDictionary();

                    WriteLength(_s, dictionary.Count);

                    foreach (KeyValuePair<string, Bincoding> item in dictionary)
                        Encode(item);

                    break;

                default:
                    _s.Write(value.Value, 0, value.Value.Length);
                    break;
            }
        }

        public void EncodeNull()
        {
            Encode(new Bincoding(BincodingType.NULL, null));
        }

        public void Encode(bool value)
        {
            Encode(Bincoding.GetValue(value));
        }

        public void Encode(byte value)
        {
            Encode(Bincoding.GetValue(value));
        }

        public void Encode(short value)
        {
            Encode(Bincoding.GetValue(value));
        }

        public void Encode(int value)
        {
            Encode(Bincoding.GetValue(value));
        }

        public void Encode(long value)
        {
            Encode(Bincoding.GetValue(value));
        }

        public void Encode(ushort value)
        {
            Encode(Bincoding.GetValue(value));
        }

        public void Encode(uint value)
        {
            Encode(Bincoding.GetValue(value));
        }

        public void Encode(ulong value)
        {
            Encode(Bincoding.GetValue(value));
        }

        public void Encode(DateTime value)
        {
            Encode(Bincoding.GetValue(value));
        }

        public void Encode(byte[] value)
        {
            Encode(Bincoding.GetValue(value));
        }

        public void Encode(IWriteStream value)
        {
            Encode(Bincoding.GetValue(value));
        }

        public void Encode(string value)
        {
            Encode(Bincoding.GetValue(value));
        }

        public void Encode(Stream value)
        {
            Encode(Bincoding.GetValue(value));
        }

        public void Encode(List<Bincoding> value)
        {
            Encode(Bincoding.GetValue(value));
        }

        public void Encode(IWriteStream[] value)
        {
            Encode(Bincoding.GetValue(value));
        }

        public void Encode(KeyValuePair<string, Bincoding> value)
        {
            Encode(Bincoding.GetValue(value));
        }

        public void Encode(string key, Bincoding value)
        {
            Encode(Bincoding.GetValue(key, value));
        }

        public void Encode(string key, bool value)
        {
            Encode(Bincoding.GetValue(key, Bincoding.GetValue(value)));
        }

        public void Encode(string key, byte value)
        {
            Encode(Bincoding.GetValue(key, Bincoding.GetValue(value)));
        }

        public void Encode(string key, short value)
        {
            Encode(Bincoding.GetValue(key, Bincoding.GetValue(value)));
        }

        public void Encode(string key, int value)
        {
            Encode(Bincoding.GetValue(key, Bincoding.GetValue(value)));
        }

        public void Encode(string key, long value)
        {
            Encode(Bincoding.GetValue(key, Bincoding.GetValue(value)));
        }

        public void Encode(string key, ushort value)
        {
            Encode(Bincoding.GetValue(key, Bincoding.GetValue(value)));
        }

        public void Encode(string key, uint value)
        {
            Encode(Bincoding.GetValue(key, Bincoding.GetValue(value)));
        }

        public void Encode(string key, ulong value)
        {
            Encode(Bincoding.GetValue(key, Bincoding.GetValue(value)));
        }

        public void Encode(string key, DateTime value)
        {
            Encode(Bincoding.GetValue(key, Bincoding.GetValue(value)));
        }

        public void Encode(string key, byte[] value)
        {
            Encode(Bincoding.GetValue(key, Bincoding.GetValue(value)));
        }

        public void Encode(string key, IWriteStream value)
        {
            Encode(Bincoding.GetValue(key, Bincoding.GetValue(value)));
        }

        public void Encode(string key, string value)
        {
            Encode(Bincoding.GetValue(key, Bincoding.GetValue(value)));
        }

        public void Encode(string key, List<Bincoding> value)
        {
            Encode(Bincoding.GetValue(key, Bincoding.GetValue(value)));
        }

        public void Encode(string key, IWriteStream[] value)
        {
            Encode(Bincoding.GetValue(key, Bincoding.GetValue(value)));
        }

        public void Encode(string key, Dictionary<string, Bincoding> value)
        {
            Encode(Bincoding.GetValue(key, Bincoding.GetValue(value)));
        }

        public void Encode(Dictionary<string, Bincoding> value)
        {
            Encode(Bincoding.GetValue(value));
        }

        #endregion

        #region properties

        public string Format
        { get { return _format; } }

        public byte Version
        { get { return _version; } }

        #endregion
    }

    public class BincodingDecoder
    {
        #region variables

        Stream _s;

        string _format;
        byte _version;

        Stream _lastStream;

        #endregion

        #region constructor

        public BincodingDecoder(Stream s)
        {
            _s = s;
        }

        public BincodingDecoder(Stream s, string format)
        {
            if (format.Length != 2)
                throw new ArgumentException("Argument 'format' must be of 2 characters.");

            byte[] buffer = new byte[2];
            OffsetStream.StreamRead(s, buffer, 0, 2);

            if (format != Encoding.ASCII.GetString(buffer))
                throw new InvalidDataException("Unable to decode: invalid data format.");

            _s = s;
            _format = format;
            _version = (byte)s.ReadByte();
        }

        #endregion

        #region private

        private int ReadLength(Stream s)
        {
            int length1 = s.ReadByte();

            if (length1 > 127)
            {
                int numberLenBytes = length1 & 0x7F;

                byte[] valueBytes = new byte[4];
                s.Read(valueBytes, 0, numberLenBytes);

                switch (numberLenBytes)
                {
                    case 1:
                        return valueBytes[0];

                    case 2:
                        Array.Reverse(valueBytes, 0, 2);
                        return BitConverter.ToInt32(valueBytes, 0);

                    case 3:
                        Array.Reverse(valueBytes, 0, 3);
                        return BitConverter.ToInt32(valueBytes, 0);

                    case 4:
                        Array.Reverse(valueBytes, 0, 4);
                        return BitConverter.ToInt32(valueBytes, 0);

                    default:
                        throw new IOException("Bincoding encoding length not supported.");
                }
            }
            else
            {
                return length1;
            }
        }

        #endregion

        #region public

        public Bincoding DecodeNext()
        {
            if (_lastStream != null)
            {
                if ((_lastStream.Length - _lastStream.Position) > 0)
                    OffsetStream.StreamCopy(_lastStream, Stream.Null, 4096, false);

                _lastStream = null;
            }

            int intType = _s.ReadByte();
            if (intType < 0)
                return null;

            BincodingType type = (BincodingType)intType;

            switch (type)
            {
                case BincodingType.NULL:
                    return new Bincoding(type, null);

                case BincodingType.BOOLEAN:
                case BincodingType.BYTE:
                    {
                        byte value = (byte)_s.ReadByte();
                        return new Bincoding(type, new byte[] { value });
                    }

                case BincodingType.SHORT:
                case BincodingType.USHORT:
                    {
                        byte[] value = new byte[2];
                        OffsetStream.StreamRead(_s, value, 0, 2);

                        return new Bincoding(type, value);
                    }

                case BincodingType.INTEGER:
                case BincodingType.UINTEGER:
                    {
                        byte[] value = new byte[4];
                        OffsetStream.StreamRead(_s, value, 0, 4);

                        return new Bincoding(type, value);
                    }

                case BincodingType.LONG:
                case BincodingType.ULONG:
                case BincodingType.DATETIME:
                    {
                        byte[] value = new byte[8];
                        OffsetStream.StreamRead(_s, value, 0, 8);

                        return new Bincoding(type, value);
                    }

                case BincodingType.BINARY:
                case BincodingType.STRING:
                    {
                        int count = ReadLength(_s);

                        byte[] value = new byte[count];
                        OffsetStream.StreamRead(_s, value, 0, count);

                        return new Bincoding(type, value);
                    }

                case BincodingType.STREAM:
                    {
                        int count = ReadLength(_s);

                        _lastStream = new OffsetStream(_s, _s.Position, count, true, false);

                        return Bincoding.GetValue(_lastStream);
                    }

                case BincodingType.LIST:
                    {
                        int count = ReadLength(_s);

                        List<Bincoding> list = new List<Bincoding>(count);

                        for (int i = 0; i < count; i++)
                            list.Add(DecodeNext());

                        return Bincoding.GetValue(list);
                    }

                case BincodingType.KEY_VALUE_PAIR:
                    {
                        int keyLen = _s.ReadByte();
                        byte[] keyBuffer = new byte[keyLen];
                        OffsetStream.StreamRead(_s, keyBuffer, 0, keyLen);

                        string key = Encoding.UTF8.GetString(keyBuffer, 0, keyLen);
                        Bincoding value = DecodeNext();

                        return Bincoding.GetValue(new KeyValuePair<string, Bincoding>(key, value));
                    }

                case BincodingType.DICTIONARY:
                    {
                        int count = ReadLength(_s);
                        Dictionary<string, Bincoding> dictionary = new Dictionary<string, Bincoding>(count);

                        for (int i = 0; i < count; i++)
                        {
                            Bincoding entry = DecodeNext();
                            KeyValuePair<string, Bincoding> pair = entry.GetKeyValuePair();

                            dictionary.Add(pair.Key, pair.Value);
                        }

                        return Bincoding.GetValue(dictionary);
                    }

                default:
                    throw new InvalidDataException("Invalid bincoding type encountered while decoding data.");
            }
        }

        #endregion

        #region properties

        public string Format
        { get { return _format; } }

        public byte Version
        { get { return _version; } }

        #endregion
    }
}
