/*
Technitium Library
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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

using NetFwTypeLib;
using System;
using System.Collections.Generic;

namespace TechnitiumLibrary.Net.Firewall
{
    public enum Protocol
    {
        Unknown = -1,
        ICMPv4 = 1,
        IGMP = 2,
        IPv4 = 4,
        TCP = 6,
        UDP = 17,
        IPv6 = 41,
        ANY = 256
    }

    public enum FirewallAction
    {
        Block = 0,
        Allow = 1
    }

    public enum InterfaceTypeFlags
    {
        All = 0,
        Lan = 1,
        Wireless = 2,
        RemoteAccess = 4
    }

    public enum Direction
    {
        Inbound = 0,
        Outbound = 1
    }

    public enum RuleStatus
    {
        DoesNotExists = 0,
        Disabled = 1,
        Allowed = 2,
        Blocked = 3
    }

    public static class WindowsFirewall
    {
        public static void AddRuleVista(string name, string description = null, FirewallAction action = FirewallAction.Allow, string applicationPath = null, Protocol protocol = Protocol.IPv4, string localPorts = null, string remotePorts = null, string localAddresses = null, string remoteAddresses = null, InterfaceTypeFlags interfaceType = InterfaceTypeFlags.All, bool enable = true, Direction direction = Direction.Inbound, bool edgeTraversal = false)
        {
            INetFwRule firewallRule = (INetFwRule)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));

            firewallRule.Name = name;
            firewallRule.Description = description;
            firewallRule.ApplicationName = applicationPath;
            firewallRule.Enabled = enable;

            firewallRule.Protocol = (int)protocol;

            if (localPorts != null)
                firewallRule.LocalPorts = localPorts;
            if (remotePorts != null)
                firewallRule.RemotePorts = remotePorts;

            if (localAddresses != null)
                firewallRule.LocalAddresses = localAddresses;
            if (remoteAddresses != null)
                firewallRule.RemoteAddresses = remoteAddresses;

            switch (direction)
            {
                case Direction.Inbound:
                    firewallRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
                    break;

                default:
                    firewallRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;
                    break;
            }

            firewallRule.EdgeTraversal = edgeTraversal;

            if (interfaceType == InterfaceTypeFlags.All)
                firewallRule.InterfaceTypes = "All";
            else
            {
                string interfaceTypeString = "";

                if ((interfaceType & InterfaceTypeFlags.Lan) > 0)
                    interfaceTypeString += ",Lan";

                if ((interfaceType & InterfaceTypeFlags.Wireless) > 0)
                    interfaceTypeString += ",Wireless";

                if ((interfaceType & InterfaceTypeFlags.RemoteAccess) > 0)
                    interfaceTypeString += ",RemoteAccess";

                if (interfaceTypeString.Length > 0)
                    firewallRule.InterfaceTypes = interfaceTypeString.Substring(1);
            }

            switch (action)
            {
                case FirewallAction.Allow:
                    firewallRule.Action = NET_FW_ACTION_.NET_FW_ACTION_ALLOW;
                    break;

                default:
                    firewallRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                    break;
            }

            INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            firewallPolicy.Rules.Add(firewallRule);
        }

        public static void RemoveRuleVista(string name, string applicationPath)
        {
            INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));

            List<INetFwRule> removeRules = new List<INetFwRule>(2);

            foreach (INetFwRule rule in firewallPolicy.Rules)
            {
                if (((rule.Name != null) && rule.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) || ((rule.ApplicationName != null) && rule.ApplicationName.Equals(applicationPath, StringComparison.OrdinalIgnoreCase)))
                    removeRules.Add(rule);
            }

            foreach (INetFwRule rule in removeRules)
            {
                firewallPolicy.Rules.Remove(rule.Name);
            }
        }

        public static RuleStatus RuleExistsVista(string name, string applicationPath, Protocol protocol = Protocol.Unknown)
        {
            INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));

            foreach (INetFwRule rule in firewallPolicy.Rules)
            {
                if (((rule.Name != null) && rule.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) || ((rule.ApplicationName != null) && rule.ApplicationName.Equals(applicationPath, StringComparison.OrdinalIgnoreCase)))
                {
                    if ((protocol != Protocol.Unknown) && (rule.Protocol != (int)protocol))
                        continue;

                    if (rule.Enabled)
                    {
                        if (rule.Action == NET_FW_ACTION_.NET_FW_ACTION_ALLOW)
                            return RuleStatus.Allowed;
                        else
                            return RuleStatus.Blocked;
                    }
                    else
                    {
                        return RuleStatus.Disabled;
                    }
                }
            }

            return RuleStatus.DoesNotExists;
        }

        public static void AddPort(string name, Protocol protocol, int port, bool enable)
        {
            INetFwOpenPort portClass = (INetFwOpenPort)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWOpenPort"));

            portClass.Name = name;
            portClass.Port = port;
            portClass.Scope = NET_FW_SCOPE_.NET_FW_SCOPE_ALL;
            portClass.Enabled = enable;

            switch (protocol)
            {
                case Protocol.UDP:
                    portClass.Protocol = NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_UDP;
                    break;

                case Protocol.TCP:
                    portClass.Protocol = NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP;
                    break;

                case Protocol.ANY:
                    portClass.Protocol = NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_ANY;
                    break;

                default:
                    throw new Exception("Protocol not supported.");
            }

            INetFwMgr firewallManager = (INetFwMgr)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));
            firewallManager.LocalPolicy.CurrentProfile.GloballyOpenPorts.Add(portClass);
        }

        public static void RemovePort(Protocol protocol, int port)
        {
            NET_FW_IP_PROTOCOL_ fwProtocol;

            switch (protocol)
            {
                case Protocol.UDP:
                    fwProtocol = NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_UDP;
                    break;

                case Protocol.TCP:
                    fwProtocol = NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP;
                    break;

                case Protocol.ANY:
                    fwProtocol = NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_ANY;
                    break;

                default:
                    throw new Exception("Protocol not supported.");
            }

            INetFwMgr firewallManager = (INetFwMgr)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));
            firewallManager.LocalPolicy.CurrentProfile.GloballyOpenPorts.Remove(port, fwProtocol);
        }

        public static bool PortExists(Protocol protocol, int port)
        {
            NET_FW_IP_PROTOCOL_ fwProtocol;

            switch (protocol)
            {
                case Protocol.UDP:
                    fwProtocol = NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_UDP;
                    break;

                case Protocol.TCP:
                    fwProtocol = NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP;
                    break;

                case Protocol.ANY:
                    fwProtocol = NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_ANY;
                    break;

                default:
                    throw new Exception("Protocol not supported.");
            }

            INetFwMgr firewallManager = (INetFwMgr)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));

            foreach (INetFwOpenPort fwPort in firewallManager.LocalPolicy.CurrentProfile.GloballyOpenPorts)
            {
                if ((fwPort.Protocol == fwProtocol) && (fwPort.Port == port))
                    return true;
            }

            return false;
        }

        public static void AddApplication(string name, string path)
        {
            INetFwAuthorizedApplication application = (INetFwAuthorizedApplication)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwAuthorizedApplication"));

            application.Name = name;
            application.ProcessImageFileName = path;
            application.Enabled = true;

            INetFwMgr firewallManager = (INetFwMgr)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));
            firewallManager.LocalPolicy.CurrentProfile.AuthorizedApplications.Add(application);
        }

        public static void RemoveApplication(string path)
        {
            INetFwMgr firewallManager = (INetFwMgr)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));
            firewallManager.LocalPolicy.CurrentProfile.AuthorizedApplications.Remove(path);
        }

        public static RuleStatus ApplicationExists(string path)
        {
            INetFwMgr firewallManager = (INetFwMgr)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));

            foreach (INetFwAuthorizedApplication app in firewallManager.LocalPolicy.CurrentProfile.AuthorizedApplications)
            {
                if (app.ProcessImageFileName.Equals(path, StringComparison.OrdinalIgnoreCase))
                {
                    if (app.Enabled)
                        return RuleStatus.Allowed;
                    else
                        return RuleStatus.Disabled;
                }
            }

            return RuleStatus.DoesNotExists;
        }
    }
}
