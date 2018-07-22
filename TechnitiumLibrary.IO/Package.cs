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
using System.Collections.ObjectModel;
using System.IO;
using System.Reflection;
using System.Text;

namespace TechnitiumLibrary.IO
{
    public enum ExtractLocation : byte
    {
        None = 0,
        WindowsRoot = 1,
        Windows = 2,
        System = 3,
        Temp = 4,
        CommonApplicationData = 5,
        CommonProgramFiles = 6,
        DesktopDirectory = 7,
        LocalApplicationData = 8,
        Personal = 9,
        ProgramFiles = 10,
        SendTo = 11,
        Programs = 12,
        StartMenu = 13,
        Startup = 14,
        Templates = 15,
        AppPath = 16,
        Custom = 255
    }

    public enum PackageMode
    {
        Create = 1,
        Open = 2
    }

    public class Package : IDisposable
    {
        #region variables

        Stream _s;
        PackageMode _mode;

        List<PackageItem> _items = new List<PackageItem>();

        readonly bool _ownStream;
        bool _closed = false;

        #endregion

        #region constructor

        public Package(string filepath, PackageMode mode)
        {
            _mode = mode;
            _ownStream = true;

            if (_mode == PackageMode.Create)
            {
                _s = new FileStream(filepath, FileMode.Create, FileAccess.Write);
                WriteHeader();
            }
            else
            {
                _s = new FileStream(filepath, FileMode.Open, FileAccess.Read);
                ReadFrom();
            }
        }

        public Package(Stream s, PackageMode mode, bool ownStream = false)
        {
            _s = s;
            _mode = mode;
            _ownStream = ownStream;

            if (mode == PackageMode.Create)
                WriteHeader();
            else
                ReadFrom();
        }

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
                if (_s != null)
                    Close();
            }

            _disposed = true;
        }

        #endregion

        #region static

        public static string GetExtractLocation(ExtractLocation extractTo, string extractToCustomLocation)
        {
            switch (extractTo)
            {
                case ExtractLocation.WindowsRoot:
                    return Path.GetPathRoot(Environment.SystemDirectory);

                case ExtractLocation.Windows:
                    return Path.GetDirectoryName(Environment.SystemDirectory);

                case ExtractLocation.System:
                    return Environment.SystemDirectory;

                case ExtractLocation.Temp:
                    return Path.GetTempPath();

                case ExtractLocation.CommonApplicationData:
                    return Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

                case ExtractLocation.CommonProgramFiles:
                    return Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFiles);

                case ExtractLocation.DesktopDirectory:
                    return Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);

                case ExtractLocation.LocalApplicationData:
                    return Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

                case ExtractLocation.Personal:
                    return Environment.GetFolderPath(Environment.SpecialFolder.Personal);

                case ExtractLocation.ProgramFiles:
                    return Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

                case ExtractLocation.SendTo:
                    return Environment.GetFolderPath(Environment.SpecialFolder.SendTo);

                case ExtractLocation.Programs:
                    return Environment.GetFolderPath(Environment.SpecialFolder.Programs);

                case ExtractLocation.StartMenu:
                    return Environment.GetFolderPath(Environment.SpecialFolder.StartMenu);

                case ExtractLocation.Startup:
                    return Environment.GetFolderPath(Environment.SpecialFolder.Startup);

                case ExtractLocation.Templates:
                    return Environment.GetFolderPath(Environment.SpecialFolder.Templates);

                case ExtractLocation.AppPath:
                    return Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);

                case ExtractLocation.Custom:
                    return extractToCustomLocation;

                default:
                    return null;
            }
        }

        #endregion

        #region private

        private void WriteHeader()
        {
            _s.Write(Encoding.ASCII.GetBytes("TP"), 0, 2); //format
            _s.WriteByte(1); //version
        }

        private void ReadFrom()
        {
            byte[] buffer = new byte[2];
            _s.Read(buffer, 0, 2); //format

            if (Encoding.ASCII.GetString(buffer) != "TP")
                throw new IOException("Invalid Package data format.");

            switch (_s.ReadByte()) //version
            {
                case -1:
                    throw new EndOfStreamException();

                case 1:
                    do
                    {
                        PackageItem item = PackageItem.Parse(_s);

                        if (item == null)
                            break;

                        _items.Add(item);

                    } while (true);

                    break;

                default:
                    throw new IOException("Package version not supported.");
            }
        }

        #endregion

        #region public

        public void AddItem(PackageItem item)
        {
            if (_closed)
                throw new ObjectDisposedException("Package");

            if (_mode != PackageMode.Create)
                throw new IOException("Package is not in create mode.");

            item.WriteTo(_s);
        }

        public void Close()
        {
            if ((_mode == PackageMode.Create) && !_closed)
            {
                _s.WriteByte(0); //eof
                _closed = true;
            }

            if (_ownStream)
                _s.Dispose();
        }

        public void ExtractAll(ExtractLocation extractTo, string extractToCustomLocation = null, bool overwrite = false)
        {
            if (_mode != PackageMode.Open)
                throw new IOException("Package is not in open mode.");

            List<PackageItemTransactionLog> oplog = new List<PackageItemTransactionLog>();

            try
            {
                foreach (PackageItem item in _items)
                {
                    PackageItemTransactionLog log;

                    if (extractTo == ExtractLocation.None)
                        log = item.Extract(overwrite);
                    else
                        log = item.Extract(extractTo, extractToCustomLocation, overwrite);

                    if (log != null)
                        oplog.Add(log);
                }

                //PROCESS ATTRIBUTES
                foreach (PackageItem item in _items)
                {
                    if (item.IsAttributeSet(PackageItemAttributes.ExecuteFile))
                    {
                        if (extractTo == ExtractLocation.None)
                            System.Diagnostics.Process.Start(item.GetExtractionFilePath());
                        else
                            System.Diagnostics.Process.Start(item.GetExtractionFilePath(extractTo, extractToCustomLocation));
                    }
                }

                //COMMIT
                foreach (PackageItemTransactionLog log in oplog)
                {
                    if (log.OriginalFilePath != null)
                    {
                        try
                        {
                            File.Delete(log.OriginalFilePath);
                        }
                        catch
                        { }
                    }
                }
            }
            catch (Exception)
            {
                //ROLLBACK
                foreach (PackageItemTransactionLog log in oplog)
                {
                    try
                    {
                        File.Delete(log.FilePath);

                        if (log.OriginalFilePath != null)
                            File.Move(log.OriginalFilePath, log.FilePath);
                    }
                    catch
                    { }
                }

                throw;
            }
        }

        public void ExtractAll(bool overwrite = false)
        {
            ExtractAll(ExtractLocation.None, null, overwrite);
        }

        #endregion

        #region properties

        public ReadOnlyCollection<PackageItem> Items
        {
            get
            {
                if (_mode != PackageMode.Open)
                    throw new IOException("Package is not in open mode.");

                return _items.AsReadOnly();
            }
        }

        #endregion
    }
}
