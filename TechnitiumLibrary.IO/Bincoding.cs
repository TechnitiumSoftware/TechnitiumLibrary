/*
Technitium Library
Copyright (C) 2018  Shreyas Zare (shreyas@technitium.com)

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
    [Obsolete]
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
        DATETIME = 15,
        SHORTSTRING = 16
    }

    [Obsolete]
    public class Bincoding
    {
        #region variables

        static readonly DateTime _epoch = new DateTime(1970, 1, 1);

        BincodingType _type;
        byte[] _value;
        Stream _stream;
        ICollection<Bincoding> _list;
        KeyValuePair<string, Bincoding> _keyValue;
        IDictionary<string, Bincoding> _dictionary;

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

        private Bincoding(ICollection<Bincoding> value)
        {
            _type = BincodingType.LIST;
            _list = value;
        }

        private Bincoding(KeyValuePair<string, Bincoding> value)
        {
            _type = BincodingType.KEY_VALUE_PAIR;
            _keyValue = value;
        }

        private Bincoding(IDictionary<string, Bincoding> value)
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

        public static Bincoding ParseValue<T>(T value)
        {
            if (value is Bincoding)
            {
                return (Bincoding)(object)value;
            }
            else if (value is bool)
            {
                return Bincoding.ParseValue((bool)(object)value);
            }
            else if (value is byte)
            {
                return Bincoding.ParseValue((byte)(object)value);
            }
            else if (value is short)
            {
                return Bincoding.ParseValue((short)(object)value);
            }
            else if (value is int)
            {
                return Bincoding.ParseValue((int)(object)value);
            }
            else if (value is long)
            {
                return Bincoding.ParseValue((long)(object)value);
            }
            else if (value is ushort)
            {
                return Bincoding.ParseValue((ushort)(object)value);
            }
            else if (value is uint)
            {
                return Bincoding.ParseValue((uint)(object)value);
            }
            else if (value is ulong)
            {
                return Bincoding.ParseValue((ulong)(object)value);
            }
            else if (value is byte[])
            {
                return Bincoding.ParseValue((byte[])(object)value);
            }
            else if (value is string)
            {
                return Bincoding.ParseValue((string)(object)value, false);
            }
            else if (value is Stream)
            {
                return Bincoding.ParseValue((Stream)(object)value);
            }
            else if (value is DateTime)
            {
                return Bincoding.ParseValue((DateTime)(object)value);
            }
            else if (value is object)
            {
                if (value == null)
                    return Bincoding.GetNullValue();

                throw new IOException("Type not supported.");
            }
            else
            {
                throw new IOException("Type not supported.");
            }
        }

        public static Bincoding ParseListValue<T>(ICollection<T> value)
        {
            List<Bincoding> list = new List<Bincoding>(value.Count);

            foreach (T item in value)
                list.Add(Bincoding.ParseValue<T>(item));

            return Bincoding.ParseListValue(list);
        }

        public static Bincoding ParseKeyValue<T>(KeyValuePair<string, T> value)
        {
            return Bincoding.ParseKeyValue(new KeyValuePair<string, Bincoding>(value.Key, Bincoding.ParseValue(value.Value)));
        }

        public static Bincoding ParseDictionaryValue<T>(IDictionary<string, T> value)
        {
            IDictionary<string, Bincoding> dict = new Dictionary<string, Bincoding>(value.Count);

            foreach (KeyValuePair<string, T> item in value)
                dict.Add(item.Key, Bincoding.ParseValue<T>(item.Value));

            return Bincoding.ParseDictionaryValue(dict);
        }

        public static Bincoding ParseValue(bool value)
        {
            return new Bincoding(BincodingType.BOOLEAN, BitConverter.GetBytes(value));
        }

        public static Bincoding ParseValue(byte value)
        {
            return new Bincoding(BincodingType.BYTE, new byte[] { value });
        }

        public static Bincoding ParseValue(short value)
        {
            return new Bincoding(BincodingType.SHORT, BitConverter.GetBytes(value));
        }

        public static Bincoding ParseValue(int value)
        {
            return new Bincoding(BincodingType.INTEGER, BitConverter.GetBytes(value));
        }

        public static Bincoding ParseValue(long value)
        {
            return new Bincoding(BincodingType.LONG, BitConverter.GetBytes(value));
        }

        public static Bincoding ParseValue(ushort value)
        {
            return new Bincoding(BincodingType.USHORT, BitConverter.GetBytes(value));
        }

        public static Bincoding ParseValue(uint value)
        {
            return new Bincoding(BincodingType.UINTEGER, BitConverter.GetBytes(value));
        }

        public static Bincoding ParseValue(ulong value)
        {
            return new Bincoding(BincodingType.ULONG, BitConverter.GetBytes(value));
        }

        public static Bincoding ParseValue(DateTime value)
        {
            return new Bincoding(BincodingType.DATETIME, BitConverter.GetBytes(Convert.ToInt64((value - _epoch).TotalMilliseconds)));
        }

        public static Bincoding ParseValue(byte[] value)
        {
            return new Bincoding(BincodingType.BINARY, value);
        }

        public static Bincoding ParseValue(IWriteStream value)
        {
            using (MemoryStream mS = new MemoryStream())
            {
                value.WriteTo(mS);

                return new Bincoding(BincodingType.BINARY, mS.ToArray());
            }
        }

        public static Bincoding ParseValue(string value, bool shortString)
        {
            if (shortString)
                return new Bincoding(BincodingType.SHORTSTRING, Encoding.UTF8.GetBytes(value));
            else
                return new Bincoding(BincodingType.STRING, Encoding.UTF8.GetBytes(value));
        }

        public static Bincoding ParseValue(Stream value)
        {
            return new Bincoding(BincodingType.STREAM, null) { _stream = value };
        }

        public static Bincoding ParseListValue(ICollection<Bincoding> value)
        {
            return new Bincoding(value);
        }

        public static Bincoding ParseBinaryListValue(IWriteStream[] value)
        {
            List<Bincoding> value2 = new List<Bincoding>(value.Length);

            foreach (IWriteStream item in value)
                value2.Add(Bincoding.ParseValue(item));

            return new Bincoding(value2);
        }

        public static Bincoding ParseKeyValue(KeyValuePair<string, Bincoding> value)
        {
            return new Bincoding(value);
        }

        public static Bincoding ParseKeyValue(string key, Bincoding value)
        {
            return new Bincoding(new KeyValuePair<string, Bincoding>(key, value));
        }

        public static Bincoding ParseDictionaryValue(IDictionary<string, Bincoding> value)
        {
            return new Bincoding(value);
        }

        #endregion

        #region public

        public T GetValue<T>()
        {
            switch (_type)
            {
                case BincodingType.NULL:
                    return default(T);

                case BincodingType.BOOLEAN:
                    return (T)(object)GetBooleanValue();

                case BincodingType.BYTE:
                    return (T)(object)GetByteValue();

                case BincodingType.SHORT:
                    return (T)(object)GetShortValue();

                case BincodingType.INTEGER:
                    return (T)(object)GetIntegerValue();

                case BincodingType.LONG:
                    return (T)(object)GetLongValue();

                case BincodingType.USHORT:
                    return (T)(object)GetUShortValue();

                case BincodingType.UINTEGER:
                    return (T)(object)GetUIntegerValue();

                case BincodingType.ULONG:
                    return (T)(object)GetULongValue();

                case BincodingType.BINARY:
                    return (T)(object)Value;

                case BincodingType.SHORTSTRING:
                case BincodingType.STRING:
                    return (T)(object)GetStringValue();

                case BincodingType.STREAM:
                    return (T)(object)GetValueStream();

                case BincodingType.LIST:
                case BincodingType.KEY_VALUE_PAIR:
                case BincodingType.DICTIONARY:
                    throw new IOException("Use special functions for list, key value pair or dictionary.");

                case BincodingType.DATETIME:
                    return (T)(object)GetBooleanValue();

                default:
                    throw new IOException("Type not supported.");
            }
        }

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

        public ICollection<Bincoding> GetList()
        {
            return _list;
        }

        public ICollection<T> GetList<T>()
        {
            List<T> list = new List<T>(_list.Count);

            foreach (Bincoding item in _list)
                list.Add(item.GetValue<T>());

            return list;
        }

        public KeyValuePair<string, Bincoding> GetKeyValuePair()
        {
            return _keyValue;
        }

        public KeyValuePair<string, T> GetKeyValuePair<T>()
        {
            return new KeyValuePair<string, T>(_keyValue.Key, _keyValue.Value.GetValue<T>());
        }

        public IDictionary<string, Bincoding> GetDictionary()
        {
            return _dictionary;
        }

        public IDictionary<string, T> GetDictionary<T>()
        {
            Dictionary<string, T> dictionary = new Dictionary<string, T>(_dictionary.Count);

            foreach (KeyValuePair<string, Bincoding> item in _dictionary)
                dictionary.Add(item.Key, item.Value.GetValue<T>());

            return dictionary;
        }

        #endregion

        #region properties

        public BincodingType Type
        { get { return _type; } }

        public byte[] Value
        { get { return _value; } }

        #endregion
    }

    [Obsolete]
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

                case BincodingType.SHORTSTRING:
                    _s.WriteByte(Convert.ToByte(value.Value.Length));
                    _s.Write(value.Value, 0, value.Value.Length);
                    break;

                case BincodingType.BINARY:
                case BincodingType.STRING:
                    WriteLength(_s, value.Value.Length);
                    _s.Write(value.Value, 0, value.Value.Length);
                    break;

                case BincodingType.STREAM:
                    Stream stream = value.GetValueStream();

                    WriteLength(_s, Convert.ToInt32(stream.Length - stream.Position));
                    stream.CopyTo(_s);
                    break;

                case BincodingType.LIST:
                    ICollection<Bincoding> list = value.GetList();

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
                    IDictionary<string, Bincoding> dictionary = value.GetDictionary();

                    WriteLength(_s, dictionary.Count);

                    foreach (KeyValuePair<string, Bincoding> item in dictionary)
                        EncodeKeyValue(item);

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
            Encode(Bincoding.ParseValue(value));
        }

        public void Encode(byte value)
        {
            Encode(Bincoding.ParseValue(value));
        }

        public void Encode(short value)
        {
            Encode(Bincoding.ParseValue(value));
        }

        public void Encode(int value)
        {
            Encode(Bincoding.ParseValue(value));
        }

        public void Encode(long value)
        {
            Encode(Bincoding.ParseValue(value));
        }

        public void Encode(ushort value)
        {
            Encode(Bincoding.ParseValue(value));
        }

        public void Encode(uint value)
        {
            Encode(Bincoding.ParseValue(value));
        }

        public void Encode(ulong value)
        {
            Encode(Bincoding.ParseValue(value));
        }

        public void Encode(DateTime value)
        {
            Encode(Bincoding.ParseValue(value));
        }

        public void Encode(byte[] value)
        {
            Encode(Bincoding.ParseValue(value));
        }

        public void EncodeBinary(IWriteStream value)
        {
            Encode(Bincoding.ParseValue(value));
        }

        public void Encode(string value, bool shortString = false)
        {
            Encode(Bincoding.ParseValue(value, shortString));
        }

        public void Encode(Stream value)
        {
            Encode(Bincoding.ParseValue(value));
        }

        public void EncodeList(ICollection<Bincoding> value)
        {
            Encode(Bincoding.ParseListValue(value));
        }

        public void EncodeList<T>(ICollection<T> value)
        {
            Encode(Bincoding.ParseListValue(value));
        }

        public void EncodeBinaryList(IWriteStream[] value)
        {
            Encode(Bincoding.ParseBinaryListValue(value));
        }

        public void EncodeKeyValue(KeyValuePair<string, Bincoding> value)
        {
            Encode(Bincoding.ParseKeyValue(value));
        }

        public void EncodeKeyValue(string key, Bincoding value)
        {
            Encode(Bincoding.ParseKeyValue(key, value));
        }

        public void EncodeKeyValue(string key, bool value)
        {
            Encode(Bincoding.ParseKeyValue(key, Bincoding.ParseValue(value)));
        }

        public void EncodeKeyValue(string key, byte value)
        {
            Encode(Bincoding.ParseKeyValue(key, Bincoding.ParseValue(value)));
        }

        public void EncodeKeyValue(string key, short value)
        {
            Encode(Bincoding.ParseKeyValue(key, Bincoding.ParseValue(value)));
        }

        public void EncodeKeyValue(string key, int value)
        {
            Encode(Bincoding.ParseKeyValue(key, Bincoding.ParseValue(value)));
        }

        public void EncodeKeyValue(string key, long value)
        {
            Encode(Bincoding.ParseKeyValue(key, Bincoding.ParseValue(value)));
        }

        public void EncodeKeyValue(string key, ushort value)
        {
            Encode(Bincoding.ParseKeyValue(key, Bincoding.ParseValue(value)));
        }

        public void EncodeKeyValue(string key, uint value)
        {
            Encode(Bincoding.ParseKeyValue(key, Bincoding.ParseValue(value)));
        }

        public void EncodeKeyValue(string key, ulong value)
        {
            Encode(Bincoding.ParseKeyValue(key, Bincoding.ParseValue(value)));
        }

        public void EncodeKeyValue(string key, DateTime value)
        {
            Encode(Bincoding.ParseKeyValue(key, Bincoding.ParseValue(value)));
        }

        public void EncodeKeyValue(string key, byte[] value)
        {
            Encode(Bincoding.ParseKeyValue(key, Bincoding.ParseValue(value)));
        }

        public void EncodeKeyValue(string key, IWriteStream value)
        {
            Encode(Bincoding.ParseKeyValue(key, Bincoding.ParseValue(value)));
        }

        public void EncodeKeyValue(string key, string value)
        {
            Encode(Bincoding.ParseKeyValue(key, Bincoding.ParseValue(value, false)));
        }

        public void EncodeKeyValue(string key, ICollection<Bincoding> value)
        {
            Encode(Bincoding.ParseKeyValue(key, Bincoding.ParseListValue(value)));
        }

        public void EncodeKeyValue(string key, IWriteStream[] value)
        {
            Encode(Bincoding.ParseKeyValue(key, Bincoding.ParseBinaryListValue(value)));
        }

        public void EncodeKeyValue(string key, IDictionary<string, Bincoding> value)
        {
            Encode(Bincoding.ParseKeyValue(key, Bincoding.ParseDictionaryValue(value)));
        }

        public void EncodeDictionary(IDictionary<string, Bincoding> value)
        {
            Encode(Bincoding.ParseDictionaryValue(value));
        }

        public void EncodeDictionary<T>(IDictionary<string, T> value)
        {
            Encode(Bincoding.ParseDictionaryValue<T>(value));
        }

        #endregion

        #region properties

        public string Format
        { get { return _format; } }

        public byte Version
        { get { return _version; } }

        #endregion
    }

    [Obsolete]
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
            s.ReadBytes(buffer, 0, 2);

            if (format != Encoding.ASCII.GetString(buffer))
                throw new InvalidDataException("Unable to decode: invalid data format.");

            _s = s;
            _format = format;

            int version = s.ReadByte();
            if (version < 0)
                throw new EndOfStreamException();

            _version = (byte)version;
        }

        #endregion

        #region private

        private int ReadLength(Stream s)
        {
            int length1 = s.ReadByte();
            if (length1 < 0)
                throw new EndOfStreamException();

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
                    _lastStream.CopyTo(Stream.Null, 4096);

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

                case BincodingType.SHORTSTRING:
                    {
                        int len = _s.ReadByte();
                        if (len < 0)
                            throw new EndOfStreamException();

                        byte[] value = new byte[len];
                        _s.ReadBytes(value, 0, value.Length);

                        return new Bincoding(type, value);
                    }

                case BincodingType.BOOLEAN:
                case BincodingType.BYTE:
                    {
                        int value = _s.ReadByte();
                        if (value < 0)
                            throw new EndOfStreamException();

                        return new Bincoding(type, new byte[] { (byte)value });
                    }

                case BincodingType.SHORT:
                case BincodingType.USHORT:
                    {
                        byte[] value = new byte[2];
                        _s.ReadBytes(value, 0, 2);

                        return new Bincoding(type, value);
                    }

                case BincodingType.INTEGER:
                case BincodingType.UINTEGER:
                    {
                        byte[] value = new byte[4];
                        _s.ReadBytes(value, 0, 4);

                        return new Bincoding(type, value);
                    }

                case BincodingType.LONG:
                case BincodingType.ULONG:
                case BincodingType.DATETIME:
                    {
                        byte[] value = new byte[8];
                        _s.ReadBytes(value, 0, 8);

                        return new Bincoding(type, value);
                    }

                case BincodingType.BINARY:
                case BincodingType.STRING:
                    {
                        int count = ReadLength(_s);

                        byte[] value = new byte[count];
                        _s.ReadBytes(value, 0, count);

                        return new Bincoding(type, value);
                    }

                case BincodingType.STREAM:
                    {
                        int count = ReadLength(_s);

                        _lastStream = new OffsetStream(_s, _s.Position, count, true, false);

                        return Bincoding.ParseValue(_lastStream);
                    }

                case BincodingType.LIST:
                    {
                        int count = ReadLength(_s);

                        List<Bincoding> list = new List<Bincoding>(count);

                        for (int i = 0; i < count; i++)
                            list.Add(DecodeNext());

                        return Bincoding.ParseListValue(list);
                    }

                case BincodingType.KEY_VALUE_PAIR:
                    {
                        int keyLen = _s.ReadByte();
                        if (keyLen < 0)
                            throw new EndOfStreamException();

                        byte[] keyBuffer = new byte[keyLen];
                        _s.ReadBytes(keyBuffer, 0, keyLen);

                        string key = Encoding.UTF8.GetString(keyBuffer, 0, keyLen);
                        Bincoding value = DecodeNext();

                        return Bincoding.ParseKeyValue(new KeyValuePair<string, Bincoding>(key, value));
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

                        return Bincoding.ParseDictionaryValue(dictionary);
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
