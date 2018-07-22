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
using System.IO;
using System.Text;

namespace TechnitiumLibrary.IO
{
    public enum PackageItemAttributes : byte
    {
        None = 0,
        FixedExtractLocation = 1,
        ExecuteFile = 2
    }

    public class PackageItem : IDisposable
    {
        #region variables

        static readonly DateTime _epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        string _name;
        DateTime _lastModifiedUTC;
        PackageItemAttributes _attributes;

        ExtractLocation _extractTo;
        string _extractToCustomLocation;

        Stream _data;
        bool _ownStream;

        #endregion

        #region constructor

        public PackageItem(string name, Stream s)
        {
            _name = name;
            _lastModifiedUTC = DateTime.UtcNow;
            _attributes = PackageItemAttributes.None;

            _extractTo = ExtractLocation.None;
            _extractToCustomLocation = null;

            _data = s;
        }

        public PackageItem(string name, DateTime lastModifiedUTC, Stream s, PackageItemAttributes attributes = PackageItemAttributes.None, ExtractLocation extractTo = ExtractLocation.None, string extractToCustomLocation = null)
        {
            _name = name;
            _lastModifiedUTC = lastModifiedUTC;
            _attributes = attributes;

            _extractTo = extractTo;

            if (extractTo == ExtractLocation.Custom)
                _extractToCustomLocation = extractToCustomLocation;

            _data = s;
        }

        public PackageItem(string filepath, PackageItemAttributes attributes = PackageItemAttributes.None, ExtractLocation extractTo = ExtractLocation.None, string extractToCustomLocation = null)
        {
            _name = Path.GetFileName(filepath);
            _lastModifiedUTC = File.GetLastWriteTimeUtc(filepath);
            _attributes = attributes;

            _extractTo = extractTo;

            if (extractTo == ExtractLocation.Custom)
                _extractToCustomLocation = extractToCustomLocation;

            _data = new FileStream(filepath, FileMode.Open, FileAccess.Read);
            _ownStream = true;
        }

        private PackageItem()
        { }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            Dispose(true);
        }

        bool _disposed = false;

        private void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_ownStream && (_data != null))
                    _data.Dispose();
            }

            _disposed = true;
        }

        #endregion

        #region static

        public static PackageItem Parse(Stream s)
        {
            int version = s.ReadByte();
            switch (version)
            {
                case -1:
                    throw new EndOfStreamException();

                case 0: //eof reached
                    return null;

                case 1:
                case 2:
                    PackageItem item = new PackageItem();

                    BinaryReader bR = new BinaryReader(s);

                    item._name = Encoding.UTF8.GetString(bR.ReadBytes(bR.ReadByte()));

                    if (version == 1)
                        item._lastModifiedUTC = DateTime.FromBinary(bR.ReadInt64());
                    else
                        item._lastModifiedUTC = _epoch.AddSeconds(bR.ReadUInt64());

                    item._attributes = (PackageItemAttributes)bR.ReadByte();

                    item._extractTo = (ExtractLocation)bR.ReadByte();
                    if (item._extractTo == ExtractLocation.Custom)
                        item._extractToCustomLocation = Encoding.UTF8.GetString(bR.ReadBytes(bR.ReadByte()));

                    long length = bR.ReadInt64();
                    item._data = new OffsetStream(bR.BaseStream, bR.BaseStream.Position, length, true);

                    bR.BaseStream.Position += length;

                    return item;

                default:
                    throw new IOException("PackageItem version not supported.");
            }
        }

        #endregion

        #region public

        public bool IsAttributeSet(PackageItemAttributes attribute)
        {
            return ((_attributes & attribute) > 0);
        }

        public void WriteTo(Stream s)
        {
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write((byte)2); //version

            byte[] buffer;

            buffer = Encoding.UTF8.GetBytes(_name);
            bW.Write(Convert.ToByte(buffer.Length));
            bW.Write(buffer, 0, buffer.Length);

            bW.Write(Convert.ToUInt64((_lastModifiedUTC - _epoch).TotalSeconds));
            bW.Write((byte)_attributes);

            bW.Write((byte)_extractTo);
            if (_extractTo == ExtractLocation.Custom)
            {
                buffer = Encoding.UTF8.GetBytes(_extractToCustomLocation);
                bW.Write(Convert.ToByte(buffer.Length));
                bW.Write(buffer, 0, buffer.Length);
            }

            bW.Write(_data.Length);
            _data.CopyTo(s);
        }

        public PackageItemTransactionLog Extract(string filepath, bool overwrite = false)
        {
            string originalFilePath = null;

            if (File.Exists(filepath))
            {
                if (overwrite)
                {
                    do
                    {
                        originalFilePath = Path.Combine(Path.GetDirectoryName(filepath), Path.GetRandomFileName());
                    } while (File.Exists(originalFilePath));

                    File.Move(filepath, originalFilePath);
                }
                else
                    return null;
            }


            using (FileStream fS = new FileStream(filepath, FileMode.Create, FileAccess.Write))
            {
                _data.Position = 0;
                _data.CopyTo(fS);
            }

            File.SetLastWriteTimeUtc(filepath, _lastModifiedUTC);

            return new PackageItemTransactionLog(filepath, originalFilePath);
        }

        public PackageItemTransactionLog Extract(ExtractLocation extractTo, string extractToCustomLocation = null, bool overwrite = false)
        {
            return Extract(GetExtractionFilePath(extractTo, extractToCustomLocation), overwrite);
        }

        public PackageItemTransactionLog Extract(bool overwrite = false)
        {
            if (_extractTo == ExtractLocation.None)
                return null;

            return Extract(GetExtractionFilePath(_extractTo, _extractToCustomLocation), overwrite);
        }

        public string GetExtractionFilePath(ExtractLocation extractTo, string extractToCustomLocation = null)
        {
            if (IsAttributeSet(PackageItemAttributes.FixedExtractLocation))
                return Path.Combine(Package.GetExtractLocation(_extractTo, _extractToCustomLocation), _name);
            else
                return Path.Combine(Package.GetExtractLocation(extractTo, extractToCustomLocation), _name);
        }

        public string GetExtractionFilePath()
        {
            return GetExtractionFilePath(_extractTo, _extractToCustomLocation);
        }

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        public DateTime LastModifiedUTC
        { get { return _lastModifiedUTC; } }

        public PackageItemAttributes Attribute
        { get { return _attributes; } }

        public ExtractLocation ExtractTo
        { get { return _extractTo; } }

        public string ExtractToCustomLocation
        { get { return _extractToCustomLocation; } }

        public Stream DataStream
        { get { return _data; } }

        #endregion
    }

    public class PackageItemTransactionLog
    {
        #region variables

        string _filepath;
        string _originalFilePath;

        #endregion

        #region constructor

        public PackageItemTransactionLog(string filepath, string originalFilePath)
        {
            _filepath = filepath;
            _originalFilePath = originalFilePath;
        }

        #endregion

        #region properties

        public string FilePath
        { get { return _filepath; } }

        public string OriginalFilePath
        { get { return _originalFilePath; } }

        #endregion
    }
}
