/*
Technitium Library
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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

using System.IO;
using System.Threading;

namespace TechnitiumLibrary.Net.Dns
{
    //Secure Nameserver Selection Algorithm for DNS Resolvers
    //https://datatracker.ietf.org/doc/draft-zhang-dnsop-ns-selection/

    //Exponentially Weighted Moving Average (EWMA)
    //EWMA(t) = alpha * r(t) + (1 - alpha) * EWMA(t-1)
    //alpha = 2 / (N + 1)

    public class NameServerMetadata
    {
        #region variables

        long _totalQueries;
        long _answeredQueries;
        double _srtt = 0; //Smoothed Round Trip Time (EWMA)
        double _sprtt = 0; //Smoothed Penalty Round Trip Time (EWMA)
        const double ALPHA = 0.25; //N=7

        #endregion

        #region constructor

        public NameServerMetadata()
        { }

        public NameServerMetadata(BinaryReader bR)
        {
            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                    _totalQueries = bR.ReadInt64();
                    _answeredQueries = bR.ReadInt64();
                    _srtt = bR.ReadDouble();
                    _sprtt = bR.ReadDouble();
                    break;

                default:
                    throw new InvalidDataException("NameServerMetadata format version not supported.");
            }
        }

        #endregion

        #region internal

        internal void UpdateSuccess(double rtt)
        {
            Interlocked.Increment(ref _totalQueries);
            Interlocked.Increment(ref _answeredQueries);

            int tries = 10;
            while (tries-- > 0)
            {
                double srtt = Volatile.Read(ref _srtt);

                double nsrtt = (ALPHA * rtt) + ((1 - ALPHA) * srtt);

                double original = Interlocked.CompareExchange(ref _srtt, nsrtt, srtt);
                if (original == srtt)
                    break;
            }
        }

        internal void UpdateFailure(double penaltyRTT)
        {
            Interlocked.Increment(ref _totalQueries);

            int tries = 10;
            while (tries-- > 0)
            {
                double sprtt = Volatile.Read(ref _sprtt);

                double nsprtt = (ALPHA * penaltyRTT) + ((1 - ALPHA) * sprtt);

                double original = Interlocked.CompareExchange(ref _sprtt, nsprtt, sprtt);
                if (original == sprtt)
                    break;
            }
        }

        #endregion

        #region public

        public double GetAnswerRate()
        {
            if (_totalQueries < 1)
                return 0;

            return _answeredQueries / (double)_totalQueries * 100d;
        }

        public double GetNetRTT()
        {
            if (_totalQueries < 1)
                return 0;

            double rate = _answeredQueries / (double)_totalQueries;

            return (rate * _srtt) + ((1 - rate) * _sprtt);
        }

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)1); //version

            bW.Write(_totalQueries);
            bW.Write(_answeredQueries);
            bW.Write(_srtt);
            bW.Write(_sprtt);
        }

        #endregion

        #region properties

        public long TotalQueries
        { get { return _totalQueries; } }

        public long AnsweredQueries
        { get { return _answeredQueries; } }

        public double SRTT
        { get { return _srtt; } }

        public double SPRTT
        { get { return _sprtt; } }

        #endregion
    }
}
