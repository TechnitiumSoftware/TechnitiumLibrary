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
using System.Net;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.BitTorrent
{
    public enum TrackerClientEvent
    {
        None = 0,
        Completed = 1,
        Started = 2,
        Stopped = 3
    }

    public abstract class TrackerClient : IDisposable
    {
        #region variables

        protected Uri _trackerURI;

        protected byte[] _infoHash;
        protected TrackerClientID _clientID;

        protected int _interval;
        protected int _minInterval = 30;

        protected NetProxy _proxy;

        protected int _leachers;
        protected int _seeders;
        protected List<IPEndPoint> _peers;

        IPEndPoint _lastClientEP;
        DateTime _lastUpdated;
        Exception _lastException;
        bool _isUpdating = false;

        #endregion

        #region constructor

        public TrackerClient(Uri trackerURI, byte[] infoHash, TrackerClientID clientID)
        {
            _trackerURI = trackerURI;

            _infoHash = infoHash;
            _clientID = clientID;

            _peers = new List<IPEndPoint>();

            _lastUpdated = DateTime.UtcNow;
        }

        #endregion

        #region IDisposable

        protected bool _disposed = false;

        ~TrackerClient()
        {
            Dispose(false);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    if (_lastClientEP != null)
                        Update(TrackerClientEvent.Stopped, _lastClientEP);
                }

                _disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion

        #region static

        public static TrackerClient Create(Uri trackerURI, byte[] infoHash, TrackerClientID clientID)
        {
            switch (trackerURI.Scheme)
            {
                case "udp":
                    return new UdpTrackerClient(trackerURI, infoHash, clientID);

                case "http":
                    return new HttpTrackerClient(trackerURI, infoHash, clientID);

                default:
                    throw new TrackerClientException("Tracker client only supports HTTP & UDP protocols.");
            }
        }

        #endregion

        #region public

        public void ScheduleUpdateNow()
        {
            lock (this)
            {
                if (_isUpdating)
                    return;
            }

            _lastUpdated = DateTime.UtcNow.AddSeconds(_interval * -1);
        }

        public TimeSpan NextUpdateIn()
        {
            return _lastUpdated.AddSeconds(_interval) - DateTime.UtcNow;
        }

        public void Update(TrackerClientEvent @event, IPEndPoint clientEP)
        {
            lock (this)
            {
                if (_isUpdating)
                    return;

                _isUpdating = true;
            }

            try
            {
                UpdateTracker(@event, clientEP);

                _lastException = null;
            }
            catch (Exception ex)
            {
                if (ex.InnerException == null)
                    _lastException = ex;
                else
                    _lastException = ex.InnerException;

                _interval = _minInterval;

                throw;
            }
            finally
            {
                _lastClientEP = clientEP;
                _lastUpdated = DateTime.UtcNow;

                lock (this)
                {
                    _isUpdating = false;
                }
            }
        }

        protected abstract void UpdateTracker(TrackerClientEvent @event, IPEndPoint clientEP);

        public override bool Equals(object obj)
        {
            TrackerClient c = obj as TrackerClient;

            if (c == null)
                return false;

            if (!_trackerURI.Equals(c._trackerURI))
                return false;

            for (int i = 0; i < 20; i++)
                if (_infoHash[i] != c._infoHash[i])
                    return false;

            return true;
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

        #endregion

        #region properties

        public Uri TrackerUri
        { get { return _trackerURI; } }

        public byte[] InfoHash
        { get { return _infoHash; } }

        public TrackerClientID ClientID
        { get { return _clientID; } }

        public int Interval
        { get { return _interval; } }

        public int MinimumInterval
        { get { return _minInterval; } }

        public int Leachers
        { get { return _leachers; } }

        public int Seeders
        { get { return _seeders; } }

        public List<IPEndPoint> Peers
        { get { return _peers; } }

        public IPEndPoint LastClientEP
        { get { return _lastClientEP; } }

        public DateTime LastUpdated
        { get { return _lastUpdated; } }

        public Exception LastException
        { get { return _lastException; } }

        public bool IsUpdating
        {
            get
            {
                lock (this)
                {
                    return _isUpdating;
                }
            }
        }

        public NetProxy Proxy
        {
            get { return _proxy; }
            set { _proxy = value; }
        }

        #endregion
    }
}
