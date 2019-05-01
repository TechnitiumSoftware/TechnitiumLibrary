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
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml;

namespace TechnitiumLibrary.Net.UPnP.Networking
{
    public class InternetGatewayDevice
    {
        #region variables

        private readonly static IPEndPoint uPnPMulticastEP = new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900);
        private readonly static byte[] uPnPRequest = Encoding.ASCII.GetBytes("M-SEARCH * HTTP/1.1\r\n" +
                                                                "HOST: 239.255.255.250:1900\r\n" +
                                                                "ST:upnp:rootdevice\r\n" +
                                                                "MAN:\"ssdp:discover\"\r\n" +
                                                                "MX:3\r\n\r\n");

        private IPAddress _deviceIP;
        private IPAddress _localIP;
        private Uri _controlUrlWanIP;
        private Uri _controlUrlWanPPP;

        #endregion

        #region constructor

        private InternetGatewayDevice(IPAddress deviceIP, IPAddress localIP, Uri controlUrlWanIP, Uri controlUrlWanPPP)
        {
            _deviceIP = deviceIP;
            _localIP = localIP;
            _controlUrlWanIP = controlUrlWanIP;
            _controlUrlWanPPP = controlUrlWanPPP;
        }

        #endregion

        #region public static

        public static InternetGatewayDevice[] Discover(IPAddress localIP, IPAddress expectedDeviceIP = null, int timeout = 2000, int maxTries = 3)
        {
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            socket.Bind(new IPEndPoint(localIP, 0));
            socket.ReceiveTimeout = timeout;
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, new MulticastOption(uPnPMulticastEP.Address, localIP));
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 1);

            Dictionary<IPAddress, InternetGatewayDevice> devices = new Dictionary<IPAddress, InternetGatewayDevice>();
            EndPoint remoteEP = new IPEndPoint(IPAddress.Any, 0);
            byte[] buffer = new byte[8 * 1024];
            int bytesRecv;

            try
            {
                for (int i = 0; i < maxTries; i++)
                {
                    //send request
                    socket.SendTo(uPnPRequest, uPnPMulticastEP);

                    //read all responses
                    while (true)
                    {
                        try
                        {
                            bytesRecv = socket.ReceiveFrom(buffer, 0, buffer.Length, SocketFlags.None, ref remoteEP);
                            if (bytesRecv < 1)
                                break;

                            //parse response
                            Uri descriptionUri = null;
                            bool isRootDevice = false;

                            using (StreamReader sR = new StreamReader(new MemoryStream(buffer, 0, bytesRecv, false)))
                            {
                                while (true)
                                {
                                    string tmp = sR.ReadLine();
                                    if (tmp == null)
                                        break;

                                    if (tmp.StartsWith("location:", StringComparison.OrdinalIgnoreCase))
                                        descriptionUri = new Uri(tmp.Substring(9).Trim());
                                    else if (tmp.StartsWith("st:", StringComparison.OrdinalIgnoreCase))
                                        isRootDevice = tmp.Substring(3).Trim().Equals("upnp:rootdevice", StringComparison.OrdinalIgnoreCase);
                                }
                            }

                            if (isRootDevice)
                            {
                                //find service URL
                                XmlDocument desc = new XmlDocument();

                                HttpWebRequest wReq = WebRequest.Create(descriptionUri) as HttpWebRequest;
                                wReq.KeepAlive = false;

                                desc.Load(wReq.GetResponse().GetResponseStream());

                                XmlNamespaceManager nsMgr = new XmlNamespaceManager(desc.NameTable);
                                nsMgr.AddNamespace("tns", "urn:schemas-upnp-org:device-1-0");

                                XmlNode typen = desc.SelectSingleNode("//tns:device/tns:deviceType/text()", nsMgr);
                                if (typen.Value.Contains("InternetGatewayDevice"))
                                {
                                    Uri controlUrlWanIP = null;
                                    Uri controlUrlWanPPP = null;
                                    XmlNode node;

                                    node = desc.SelectSingleNode("//tns:service[tns:serviceType=\"urn:schemas-upnp-org:service:WANIPConnection:1\"]/tns:controlURL/text()", nsMgr);
                                    if (node != null)
                                    {
                                        if (node.Value.StartsWith("http:", StringComparison.OrdinalIgnoreCase))
                                            controlUrlWanIP = new Uri(node.Value);
                                        else
                                            controlUrlWanIP = new Uri(descriptionUri, node.Value);
                                    }

                                    node = desc.SelectSingleNode("//tns:service[tns:serviceType=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"]/tns:controlURL/text()", nsMgr);
                                    if (node != null)
                                    {
                                        if (node.Value.StartsWith("http:", StringComparison.OrdinalIgnoreCase))
                                            controlUrlWanPPP = new Uri(node.Value);
                                        else
                                            controlUrlWanPPP = new Uri(descriptionUri, node.Value);
                                    }

                                    if ((controlUrlWanIP != null) || (controlUrlWanPPP != null))
                                    {
                                        IPAddress deviceIP = (remoteEP as IPEndPoint).Address;

                                        if (deviceIP.Equals(expectedDeviceIP))
                                            return new InternetGatewayDevice[] { new InternetGatewayDevice(deviceIP, localIP, controlUrlWanIP, controlUrlWanPPP) };

                                        if (!devices.ContainsKey(deviceIP))
                                            devices.Add(deviceIP, new InternetGatewayDevice(deviceIP, localIP, controlUrlWanIP, controlUrlWanPPP));
                                    }
                                }
                            }
                        }
                        catch (SocketException)
                        {
                            break;
                        }
                        catch
                        {
                            //ignore other errors
                        }
                    }
                }
            }
            finally
            {
                socket.Close();
            }

            if (devices.Count > 0)
            {
                InternetGatewayDevice[] igDevices = new InternetGatewayDevice[devices.Count];
                devices.Values.CopyTo(igDevices, 0);

                return igDevices;
            }

            return new InternetGatewayDevice[] { };
        }

        #endregion

        #region private

        private HttpWebResponse SOAPRequest(string SOAP, string functionName)
        {
            Exception exPPP = null;

            if (_controlUrlWanPPP != null)
            {
                try
                {
                    return SOAPRequest(_controlUrlWanPPP, SOAP, functionName, "WANPPPConnection");
                }
                catch (WebException ex)
                {
                    exPPP = ex;
                }
            }

            if (_controlUrlWanIP != null)
            {
                try
                {
                    return SOAPRequest(_controlUrlWanIP, SOAP.Replace("service:WANPPPConnection:1", "service:WANIPConnection:1"), functionName, "WANIPConnection");
                }
                catch (WebException ex)
                {
                    if (exPPP != null)
                        throw new InternetGatewayDeviceException("Server returned an error.", exPPP);
                    else
                        throw new InternetGatewayDeviceException("Server returned an error.", ex);
                }
            }

            throw new InternetGatewayDeviceException("No control URL available to make UPnP SOAP request.");
        }

        private static HttpWebResponse SOAPRequest(Uri controlURL, string SOAP, string functionName, string WANService)
        {
            string request = "<?xml version=\"1.0\"?>\r\n" +
                            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n" +
                            "<s:Body>\r\n" +
                            SOAP + "\r\n" +
                            "</s:Body>\r\n" +
                            "</s:Envelope>";

            byte[] buffer = Encoding.ASCII.GetBytes(request);

            HttpWebRequest wReq = WebRequest.Create(controlURL) as HttpWebRequest;
            wReq.Method = "POST";
            wReq.Headers.Add("SOAPACTION", "\"urn:schemas-upnp-org:service:" + WANService + ":1#" + functionName + "\"");
            wReq.KeepAlive = false;
            wReq.ContentType = "text/xml; charset=\"utf-8\"";
            wReq.ContentLength = buffer.Length;
            wReq.GetRequestStream().Write(buffer, 0, buffer.Length);

            HttpWebResponse response;

            try
            {
                response = (HttpWebResponse)wReq.GetResponse();
            }
            catch (WebException ex)
            {
                response = (HttpWebResponse)ex.Response;
            }

            int statusCode = (int)response.StatusCode;

            switch (statusCode)
            {
                case 401:
                    throw new InternetGatewayDeviceException("UPnP device returned an error: (" + statusCode + ") Invalid Action.");

                case 402:
                    throw new InternetGatewayDeviceException("UPnP device returned an error: (" + statusCode + ") Invalid Args.");

                case 404:
                    throw new InternetGatewayDeviceException("UPnP device returned an error: (" + statusCode + ") Invalid Var.");

                case 501:
                    throw new InternetGatewayDeviceException("UPnP device returned an error: (" + statusCode + ") Action Failed.");

                case 500:
                    try
                    {
                        XmlDocument xResp = new XmlDocument();
                        xResp.Load(response.GetResponseStream());

                        XmlNamespaceManager nsMgr = new XmlNamespaceManager(xResp.NameTable);
                        nsMgr.AddNamespace("s", "http://schemas.xmlsoap.org/soap/envelope/");

                        XmlNode nodeFaultDetail = xResp.SelectSingleNode("//s:Envelope/s:Body/s:Fault/detail", nsMgr);

                        if (nodeFaultDetail != null)
                        {
                            XmlNode nodeDetailItem = nodeFaultDetail.FirstChild;

                            if (nodeDetailItem != null)
                            {
                                int errorCode = -1;
                                string errorDescription = "unknown";

                                foreach (XmlNode nodeChild in nodeDetailItem.ChildNodes)
                                {
                                    switch (nodeChild.LocalName)
                                    {
                                        case "errorCode":
                                            errorCode = int.Parse(nodeChild.InnerText);
                                            break;

                                        case "errorDescription":
                                            errorDescription = nodeChild.InnerText;
                                            break;
                                    }
                                }

                                throw new InternetGatewayDeviceException(errorCode, "UPnP device returned an error: (" + errorCode + ") " + errorDescription);
                            }
                        }
                    }
                    catch (InternetGatewayDeviceException)
                    {
                        throw;
                    }
                    catch
                    {
                        //ignore any response xml parsing errors
                    }

                    //throw generic error
                    throw new InternetGatewayDeviceException("UPnP device returned an error: (" + statusCode + ") Internal Server Error.");

                default:
                    return response;
            }
        }

        #endregion

        #region public

        public void AddPortMapping(ProtocolType protocol, int externalPort, IPEndPoint internalEP, string description, bool enabled = true, uint leaseDuration = 0)
        {
            string SOAP = "<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\">" +
                                "<NewRemoteHost></NewRemoteHost><NewExternalPort>" + externalPort + "</NewExternalPort><NewProtocol>" + protocol.ToString().ToUpper() + "</NewProtocol>" +
                                "<NewInternalPort>" + internalEP.Port + "</NewInternalPort><NewInternalClient>" + internalEP.Address.ToString() + "</NewInternalClient>" +
                                "<NewEnabled>" + (enabled ? "1" : "0") + "</NewEnabled><NewPortMappingDescription>" + description + "</NewPortMappingDescription>" +
                                "<NewLeaseDuration>" + leaseDuration + "</NewLeaseDuration>" +
                           "</u:AddPortMapping>";

            HttpWebResponse response = SOAPRequest(SOAP, "AddPortMapping");

            int statusCode = Convert.ToInt32(response.StatusCode);

            switch (statusCode)
            {
                case 200: //success
                    break;

                case 715:
                    throw new InternetGatewayDeviceException("UPnP device returned an error: (" + statusCode + ") The source IP address cannot be wild-carded.");

                case 716:
                    throw new InternetGatewayDeviceException("UPnP device returned an error: (" + statusCode + ") The external port cannot be wild-carded.");

                case 718:
                    throw new InternetGatewayDeviceException("UPnP device returned an error: (" + statusCode + ") The port mapping entry specified conflicts with a mapping assigned previously to another client.");

                case 724:
                    throw new InternetGatewayDeviceException("UPnP device returned an error: (" + statusCode + ") Internal and External port values must be the same.");

                case 725:
                    throw new InternetGatewayDeviceException("UPnP device returned an error: (" + statusCode + ") The NAT implementation only supports permanent lease times on port mappings.");

                case 726:
                    throw new InternetGatewayDeviceException("UPnP device returned an error: (" + statusCode + ") RemoteHost must be a wildcard and cannot be a specific IP address or DNS name.");

                case 727:
                    throw new InternetGatewayDeviceException("UPnP device returned an error: (" + statusCode + ") ExternalPort must be a wildcard and cannot be a specific port value.");

                default:
                    throw new InternetGatewayDeviceException("UPnP device returned an error: (" + statusCode + ") " + response.StatusDescription);
            }
        }

        public void DeletePortMapping(ProtocolType protocol, int externalPort)
        {
            string SOAP = "<u:DeletePortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\">" +
                                "<NewRemoteHost></NewRemoteHost>" +
                                "<NewExternalPort>" + externalPort + "</NewExternalPort>" +
                                "<NewProtocol>" + protocol.ToString().ToUpper() + "</NewProtocol>" +
                          "</u:DeletePortMapping>";

            HttpWebResponse response = SOAPRequest(SOAP, "DeletePortMapping");

            int statusCode = Convert.ToInt32(response.StatusCode);

            switch (statusCode)
            {
                case 200: //success
                    break;

                case 714:
                    throw new InternetGatewayDeviceException("UPnP device returned an error: (" + statusCode + ") The specified value does not exists in the array.");

                default:
                    throw new InternetGatewayDeviceException("UPnP device returned an error: (" + statusCode + ") " + response.StatusDescription);
            }
        }

        public IPAddress GetExternalIPAddress()
        {
            string SOAP = "<u:GetExternalIPAddress xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"></u:GetExternalIPAddress>";

            HttpWebResponse response = SOAPRequest(SOAP, "GetExternalIPAddress");

            int statusCode = Convert.ToInt32(response.StatusCode);

            switch (statusCode)
            {
                case 200:
                    //success
                    XmlDocument xResp = new XmlDocument();
                    xResp.Load(response.GetResponseStream());

                    XmlNamespaceManager nsMgr = new XmlNamespaceManager(xResp.NameTable);
                    XmlNode node = xResp.SelectSingleNode("//NewExternalIPAddress/text()", nsMgr);

                    return IPAddress.Parse(node.Value);

                default:
                    throw new InternetGatewayDeviceException("UPnP device returned an error: (" + statusCode + ") " + response.StatusDescription);
            }
        }

        public PortMappingEntry GetSpecificPortMappingEntry(ProtocolType protocol, int externalPort)
        {
            string SOAP = "<u:GetSpecificPortMappingEntry xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\">" +
                                "<NewRemoteHost></NewRemoteHost>" +
                                "<NewExternalPort>" + externalPort + "</NewExternalPort>" +
                                "<NewProtocol>" + protocol.ToString().ToUpper() + "</NewProtocol>" +
                           "</u:GetSpecificPortMappingEntry>";

            HttpWebResponse response;

            try
            {
                response = SOAPRequest(SOAP, "GetSpecificPortMappingEntry");
            }
            catch (InternetGatewayDeviceException ex)
            {
                switch (ex.ErrorCode)
                {
                    case 714:
                        //The specified value does not exists in the array
                        return null;

                    default:
                        throw;
                }
            }

            int statusCode = Convert.ToInt32(response.StatusCode);

            switch (statusCode)
            {
                case 200:
                    //success
                    XmlDocument xResp = new XmlDocument();
                    xResp.Load(response.GetResponseStream());

                    XmlNamespaceManager nsMgr = new XmlNamespaceManager(xResp.NameTable);

                    XmlNode node1 = xResp.SelectSingleNode("//NewInternalPort/text()", nsMgr);
                    XmlNode node2 = xResp.SelectSingleNode("//NewInternalClient/text()", nsMgr);
                    XmlNode node3 = xResp.SelectSingleNode("//NewEnabled/text()", nsMgr);
                    XmlNode node4 = xResp.SelectSingleNode("//NewPortMappingDescription/text()", nsMgr);
                    XmlNode node5 = xResp.SelectSingleNode("//NewLeaseDuration/text()", nsMgr);

                    return new PortMappingEntry(Convert.ToInt32(node1.Value), IPAddress.Parse(node2.Value), Convert.ToBoolean(Convert.ToInt32(node3.Value)), node4.Value, Convert.ToInt32(node5.Value));

                case 714:
                    //The specified value does not exists in the array
                    return null;

                default:
                    throw new InternetGatewayDeviceException(statusCode, "UPnP device returned an error: (" + statusCode + ") " + response.StatusDescription);
            }
        }

        public GenericPortMappingEntry GetGenericPortMappingEntry(int portMappingIndex)
        {
            string SOAP = "<u:GetGenericPortMappingEntry xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\">" +
                                "<NewPortMappingIndex>" + portMappingIndex + "</NewPortMappingIndex>" +
                          "</u:GetGenericPortMappingEntry>";

            HttpWebResponse response;

            try
            {
                response = SOAPRequest(SOAP, "GetGenericPortMappingEntry");
            }
            catch (InternetGatewayDeviceException ex)
            {
                switch (ex.ErrorCode)
                {
                    case 713:
                        //The specified array index is out of bound
                        return null;

                    default:
                        throw;
                }
            }

            int statusCode = Convert.ToInt32(response.StatusCode);

            switch (statusCode)
            {
                case 200:
                    //success
                    XmlDocument xResp = new XmlDocument();
                    xResp.Load(response.GetResponseStream());

                    XmlNamespaceManager nsMgr = new XmlNamespaceManager(xResp.NameTable);
                    XmlNode node1 = xResp.SelectSingleNode("//NewRemoteHost/text()", nsMgr);

                    IPAddress RemoteHost = null;
                    if (node1 == null)
                        RemoteHost = IPAddress.Any;
                    else
                        RemoteHost = IPAddress.Parse(node1.Value);

                    XmlNode node2 = xResp.SelectSingleNode("//NewExternalPort/text()", nsMgr);
                    XmlNode node3 = xResp.SelectSingleNode("//NewProtocol/text()", nsMgr);
                    XmlNode node4 = xResp.SelectSingleNode("//NewInternalPort/text()", nsMgr);
                    XmlNode node5 = xResp.SelectSingleNode("//NewInternalClient/text()", nsMgr);
                    XmlNode node6 = xResp.SelectSingleNode("//NewEnabled/text()", nsMgr);
                    XmlNode node7 = xResp.SelectSingleNode("//NewPortMappingDescription/text()", nsMgr);
                    XmlNode node8 = xResp.SelectSingleNode("//NewLeaseDuration/text()", nsMgr);

                    return new GenericPortMappingEntry(RemoteHost, Convert.ToInt32(node2.Value), (ProtocolType)Enum.Parse(typeof(ProtocolType), node3.Value, true), Convert.ToInt32(node4.Value), IPAddress.Parse(node5.Value), Convert.ToBoolean(Convert.ToInt32(node6.Value)), node7.Value, Convert.ToInt32(node8.Value));

                case 713:
                    //The specified array index is out of bound
                    return null;

                default:
                    throw new InternetGatewayDeviceException("UPnP device returned an error: (" + statusCode + ") " + response.StatusDescription);
            }
        }

        public bool ForwardPort(ProtocolType protocol, int externalPort, IPEndPoint internalEP, string description = "", bool force = false, uint leaseDuration = 0)
        {
            try
            {
                PortMappingEntry portMap = GetSpecificPortMappingEntry(protocol, externalPort);

                if (portMap != null)
                {
                    if (portMap.InternalEP.Equals(internalEP))
                    {
                        //external port already mapped
                        return true;
                    }
                    else
                    {
                        //external port not available
                        if (force)
                            DeletePortMapping(protocol, externalPort);
                        else
                            return false;
                    }
                }
            }
            catch
            { }

            try
            {
                AddPortMapping(protocol, externalPort, internalEP, description, true, leaseDuration);
                return true;
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region properties

        public IPAddress DeviceIP
        { get { return _deviceIP; } }

        public IPAddress LocalIP
        { get { return _localIP; } }

        #endregion
    }
}