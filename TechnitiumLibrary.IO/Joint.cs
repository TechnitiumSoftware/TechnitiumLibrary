/*
Technitium Library
Copyright (C) 2020  Shreyas Zare (shreyas@technitium.com)

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
using System.Threading.Tasks;

namespace TechnitiumLibrary.IO
{
    public class Joint : IDisposable
    {
        #region events

        public event EventHandler Disposing;

        #endregion

        #region variables

        readonly Stream _stream1;
        readonly Stream _stream2;

        #endregion

        #region constructor

        public Joint(Stream stream1, Stream stream2)
        {
            _stream1 = stream1;
            _stream2 = stream2;
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            Dispose(true);
        }

        bool _disposed = false;
        readonly object _disposeLock = new object();

        protected virtual void Dispose(bool disposing)
        {
            lock (_disposeLock)
            {
                if (_disposed)
                    return;

                _disposed = true; //set true before event call to prevent loop

                if (disposing)
                {
                    Disposing?.Invoke(this, EventArgs.Empty);

                    if (_stream1 != null)
                        _stream1.Dispose();

                    if (_stream2 != null)
                        _stream2.Dispose();
                }
            }
        }

        #endregion

        #region private

        private async Task CopyToAsync(Stream src, Stream dst)
        {
            try
            {
                await src.CopyToAsync(dst);
            }
            finally
            {
                Dispose();
            }
        }

        #endregion

        #region public

        public void Start()
        {
            _ = CopyToAsync(_stream1, _stream2);
            _ = CopyToAsync(_stream2, _stream1);
        }

        #endregion

        #region properties

        public Stream Stream1
        { get { return _stream1; } }

        public Stream Stream2
        { get { return _stream2; } }

        #endregion
    }
}
