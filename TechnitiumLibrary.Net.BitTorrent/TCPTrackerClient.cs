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
using System.Web;

namespace TechnitiumLibrary.Net.BitTorrent
{
    class TCPTrackerClient : TrackerClient
    {
        #region constructor

        public TCPTrackerClient(Uri trackerURI, byte[] infoHash, TrackerClientID clientID)
            : base(trackerURI, infoHash, clientID)
        { }

        #endregion

        #region private

        private static List<IPEndPoint> ParseCompactPeers(byte[] data)
        {
            List<IPEndPoint> peers = new List<IPEndPoint>();
            byte[] ipBuffer = new byte[4];
            byte[] portBuffer = new byte[2];

            for (int i = 0; i < data.Length; i += 6)
            {
                Buffer.BlockCopy(data, i, ipBuffer, 0, 4);
                Buffer.BlockCopy(data, i + 4, portBuffer, 0, 2);
                Array.Reverse(portBuffer);

                IPAddress peerIP = new IPAddress(ipBuffer);
                switch (peerIP.ToString())
                {
                    case "0.0.0.0":
                    case "127.0.0.1":
                        break;

                    default:
                        peers.Add(new IPEndPoint(peerIP, BitConverter.ToUInt16(portBuffer, 0)));
                        break;
                }
            }

            return peers;
        }

        #endregion

        #region protected

        protected override void UpdateTracker(TrackerClientEvent @event, IPEndPoint clientEP)
        {
            string queryString;

            queryString = "?info_hash=" + HttpUtility.UrlEncode(_infoHash) +
                          "&peer_id=" + HttpUtility.UrlEncode(_clientID.PeerID);

            switch (clientEP.Address.ToString())
            {
                case "0.0.0.0":
                case "127.0.0.1":
                    break;

                default:
                    queryString += "&ip=" + clientEP.Address.ToString();
                    break;
            }

            queryString += "&port=" + clientEP.Port +
                        "&uploaded=0&downloaded=0&left=0&corrupt=0" +
                        "&key=" + BitConverter.ToString(_clientID.ClientKey).Replace("-", "");

            switch (@event)
            {
                case TrackerClientEvent.Started:
                    queryString += "&event=started";
                    break;

                case TrackerClientEvent.Stopped:
                    queryString += "&event=stopped";
                    break;

                case TrackerClientEvent.Completed:
                    queryString += "&event=completed";
                    break;
            }

            queryString += "&numwant=" + _clientID.NumWant;

            if (_clientID.Compact)
                queryString += "&compact=1";
            else
                queryString += "&compact=0";

            if (_clientID.NoPeerID)
                queryString += "&no_peer_id=1";

            HttpWebRequest wReq = (HttpWebRequest)HttpWebRequest.Create(_trackerURI.AbsoluteUri + queryString);

            wReq.UserAgent = _clientID.HttpUserAgent;
            wReq.Headers.Add("Accept-Encoding", _clientID.HttpAcceptEncoding);
            wReq.KeepAlive = false;

            WebResponse wR = wReq.GetResponse();

            switch (@event)
            {
                case TrackerClientEvent.None:
                case TrackerClientEvent.Started:
                    Bencoding x = Bencoding.Decode(wR.GetResponseStream());

                    switch (x.Type)
                    {
                        case BencodingType.Dictionary:
                            foreach (var item in x.ValueDictionary)
                            {
                                switch (item.Key)
                                {
                                    case "peers":
                                        switch (item.Value.Type)
                                        {
                                            case BencodingType.Dictionary:
                                                //_peers = ParseCompactPeers(item.Value.Value as byte[]);
                                                break;

                                            case BencodingType.String:
                                                _peers = ParseCompactPeers(item.Value.Value as byte[]);
                                                break;
                                        }
                                        break;

                                    case "interval":
                                        if (item.Value.Type == BencodingType.Integer)
                                            _interval = Convert.ToInt32(item.Value.Value);
                                        break;

                                    case "min interval":
                                        if (item.Value.Type == BencodingType.Integer)
                                            _minInterval = Convert.ToInt32(item.Value.Value);
                                        break;
                                }
                            }
                            break;

                        default:
                            throw new TrackerClientException("Invalid data received from tracker. Expected bencoded dictionary.");
                    }
                    break;
            }
        }

        #endregion
    }
}