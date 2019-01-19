/*
Technitium Library
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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
using System.Threading;

namespace TechnitiumLibrary.IO
{
    public class Joint : IDisposable
    {
        #region variables

        const int BUFFER_SIZE = 4096;

        readonly Stream _stream1;
        readonly Stream _stream2;
        readonly WaitCallback _onDisposed;

        Thread _worker1;
        Thread _worker2;

        #endregion

        #region constructor

        public Joint(Stream stream1, Stream stream2, WaitCallback onDisposed = null)
        {
            _stream1 = stream1;
            _stream2 = stream2;
            _onDisposed = onDisposed;
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            Dispose(true);
        }

        bool _disposed = false;
        readonly object _disposeLock = new object();

        private void Dispose(bool disposing)
        {
            lock (_disposeLock)
            {
                if (_disposed)
                    return;

                if (disposing)
                {
                    if (_stream1 != null)
                        _stream1.Dispose();

                    if (_stream2 != null)
                        _stream2.Dispose();
                }

                _disposed = true;
                _onDisposed?.Invoke(this);
            }
        }

        #endregion

        #region public

        public void Start()
        {
            _worker1 = new Thread(ForwardData1To2);
            _worker1.IsBackground = true;

            _worker2 = new Thread(ForwardData2To1);
            _worker2.IsBackground = true;

            _worker1.Start();
            _worker2.Start();
        }

        #endregion

        #region private

        private void ForwardData1To2()
        {
            try
            {
                _stream1.CopyTo(_stream2, BUFFER_SIZE);
            }
            catch
            { }
            finally
            {
                Dispose();
            }
        }

        private void ForwardData2To1()
        {
            try
            {
                _stream2.CopyTo(_stream1, BUFFER_SIZE);
            }
            catch
            { }
            finally
            {
                Dispose();
            }
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
