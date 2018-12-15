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

        int _customUpdateInterval;

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
        int _retriesDone;

        readonly object _isUpdatingLock = new object();

        #endregion

        #region constructor

        protected TrackerClient(Uri trackerURI, byte[] infoHash, TrackerClientID clientID, int customUpdateInterval)
        {
            _trackerURI = trackerURI;

            _infoHash = infoHash;
            _clientID = clientID;

            _customUpdateInterval = customUpdateInterval;

            _peers = new List<IPEndPoint>();

            ScheduleUpdateNow();
        }

        #endregion

        #region IDisposable

        protected bool _disposed = false;

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_lastClientEP != null)
                    Update(TrackerClientEvent.Stopped, _lastClientEP);
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region static

        public static TrackerClient Create(Uri trackerURI, byte[] infoHash, TrackerClientID clientID, int customUpdateInterval = 0)
        {
            switch (trackerURI.Scheme)
            {
                case "udp":
                    return new UdpTrackerClient(trackerURI, infoHash, clientID, customUpdateInterval);

                case "http":
                case "https":
                    return new HttpTrackerClient(trackerURI, infoHash, clientID, customUpdateInterval);

                default:
                    throw new TrackerClientException("Tracker client only supports HTTP & UDP protocols.");
            }
        }

        #endregion

        #region private

        private int GetUpdateInterval()
        {
            if (_customUpdateInterval > 0)
                return _customUpdateInterval;

            return _interval;
        }

        #endregion

        #region public

        public void ScheduleUpdateNow()
        {
            lock (_isUpdatingLock)
            {
                if (_isUpdating)
                    return;
            }

            _lastUpdated = DateTime.UtcNow.AddSeconds(GetUpdateInterval() * -1);
        }

        public TimeSpan NextUpdateIn()
        {
            return _lastUpdated.AddSeconds(GetUpdateInterval()) - DateTime.UtcNow;
        }

        public void Update(TrackerClientEvent @event, IPEndPoint clientEP)
        {
            lock (_isUpdatingLock)
            {
                if (_isUpdating)
                    return;

                _isUpdating = true;
            }

            try
            {
                UpdateTracker(@event, clientEP);

                _lastException = null;
                _retriesDone = 0;
            }
            catch (Exception ex)
            {
                if (ex.InnerException == null)
                    _lastException = ex;
                else
                    _lastException = ex.InnerException;

                _retriesDone++;
                _interval = _minInterval;

                throw;
            }
            finally
            {
                _lastClientEP = clientEP;
                _lastUpdated = DateTime.UtcNow;

                lock (_isUpdatingLock)
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

        public int CustomUpdateInterval
        {
            get { return _customUpdateInterval; }
            set { _customUpdateInterval = value; }
        }

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
                lock (_isUpdatingLock)
                {
                    return _isUpdating;
                }
            }
        }

        public int RetriesDone
        { get { return _retriesDone; } }

        public NetProxy Proxy
        {
            get { return _proxy; }
            set { _proxy = value; }
        }

        #endregion
    }
}
