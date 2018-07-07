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
using System.Threading;

namespace TechnitiumLibrary.IO
{
    public class Joint : IDisposable
    {
        #region events

        public event EventHandler Disposed;

        #endregion

        #region variables

        const int BUFFER_SIZE = 65536;

        Stream _stream1;
        Stream _stream2;

        Thread _worker1;
        Thread _worker2;

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
            GC.SuppressFinalize(this);
        }

        bool _disposed = false;

        private void Dispose(bool disposing)
        {
            lock (this)
            {
                if (_disposed)
                    return;

                if (disposing)
                {
                    if (_stream1 != null)
                        _stream1.Dispose();

                    if (_stream2 != null)
                        _stream2.Dispose();

                    Disposed?.Invoke(this, EventArgs.Empty);
                }

                _disposed = true;
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
                OffsetStream.StreamCopy(_stream1, _stream2, BUFFER_SIZE, true);
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
                OffsetStream.StreamCopy(_stream2, _stream1, BUFFER_SIZE, true);
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
