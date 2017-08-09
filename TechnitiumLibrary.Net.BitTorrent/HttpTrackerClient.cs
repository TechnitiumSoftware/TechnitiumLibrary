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
using System.IO;
using System.Net;
using System.Text;

namespace TechnitiumLibrary.Net.BitTorrent
{
    class HttpTrackerClient : TrackerClient
    {
        #region constructor

        public HttpTrackerClient(Uri trackerURI, byte[] infoHash, TrackerClientID clientID, int customUpdateInterval = 0)
            : base(trackerURI, infoHash, clientID, customUpdateInterval)
        { }

        #endregion

        #region private

        private static void ParseCompactPeersIPv4(byte[] data, List<IPEndPoint> peers)
        {
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
        }

        private static void ParseCompactPeersIPv6(byte[] data, List<IPEndPoint> peers)
        {
            byte[] ipBuffer = new byte[16];
            byte[] portBuffer = new byte[2];

            for (int i = 0; i < data.Length; i += 18)
            {
                Buffer.BlockCopy(data, i, ipBuffer, 0, 16);
                Buffer.BlockCopy(data, i + 16, portBuffer, 0, 2);
                Array.Reverse(portBuffer);

                IPAddress peerIP = new IPAddress(ipBuffer);
                switch (peerIP.ToString())
                {
                    case "::":
                    case "::1":
                        break;

                    default:
                        peers.Add(new IPEndPoint(peerIP, BitConverter.ToUInt16(portBuffer, 0)));
                        break;
                }
            }
        }

        #endregion

        #region protected

        protected override void UpdateTracker(TrackerClientEvent @event, IPEndPoint clientEP)
        {
            string queryString;

            queryString = "?info_hash=" + Uri.EscapeDataString(Encoding.ASCII.GetString(_infoHash)) +
                          "&peer_id=" + Uri.EscapeDataString(Encoding.ASCII.GetString(_clientID.PeerID));

            switch (clientEP.Address.ToString())
            {
                case "0.0.0.0":
                case "127.0.0.1":
                case "::":
                case "::1":
                    break;

                default:
                    if (clientEP.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                        queryString += "&ipv6=" + clientEP.Address.ToString();
                    else
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
            
            using (WebClientEx webClient = new WebClientEx())
            {
                webClient.Proxy = _proxy;
                webClient.Timeout = 30000; //30 sec timeout
                webClient.UserAgent = _clientID.HttpUserAgent;
                webClient.AddHeader("Accept-Encoding", _clientID.HttpAcceptEncoding);
                webClient.KeepAlive = false;

                using (Stream responseStream = webClient.OpenRead(_trackerURI.AbsoluteUri + queryString))
                {
                    switch (@event)
                    {
                        case TrackerClientEvent.None:
                        case TrackerClientEvent.Started:
                            Bencoding x = Bencoding.Decode(responseStream);

                            switch (x.Type)
                            {
                                case BencodingType.Dictionary:
                                    _peers.Clear();

                                    foreach (var item in x.ValueDictionary)
                                    {
                                        switch (item.Key)
                                        {
                                            case "peers":
                                                switch (item.Value.Type)
                                                {
                                                    case BencodingType.String:
                                                        ParseCompactPeersIPv4(item.Value.Value as byte[], _peers);
                                                        break;

                                                    case BencodingType.List:
                                                        foreach (var peerObj in item.Value.ValueList)
                                                        {
                                                            var peer = peerObj.ValueDictionary;

                                                            _peers.Add(new IPEndPoint(IPAddress.Parse(peer["ip"].ValueString), Convert.ToInt32(peer["port"].ValueInteger)));
                                                        }
                                                        break;
                                                }
                                                break;

                                            case "peers_ipv6":
                                            case "peers6":
                                                switch (item.Value.Type)
                                                {
                                                    case BencodingType.String:
                                                        ParseCompactPeersIPv6(item.Value.Value as byte[], _peers);
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
            }
        }

        #endregion
    }
}