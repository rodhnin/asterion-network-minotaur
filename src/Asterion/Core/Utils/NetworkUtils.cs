using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Serilog;

namespace Asterion.Core.Utils
{
    /// <summary>
    /// Network utility functions for Asterion
    /// Provides helpers for port scanning, banner grabbing, connectivity tests, and target parsing
    /// </summary>
    public static class NetworkUtils
    {
        #region Target Parsing

        /// <summary>
        /// Parse target string into list of targets
        /// Delegates to CidrParser for actual parsing logic
        /// </summary>
        /// <param name="target">Target string to parse</param>
        /// <returns>List of individual target IPs/hostnames</returns>
        public static List<string> ParseTargets(string target)
        {
            return CidrParser.ParseTargets(target);
        }

        #endregion

        #region Port Scanning & Connectivity

        /// <summary>
        /// Check if a port is open on a remote host
        /// Supports both TCP and UDP protocols
        /// </summary>
        /// <param name="host">Target hostname or IP address</param>
        /// <param name="port">Port number to check</param>
        /// <param name="timeoutMs">Timeout in milliseconds</param>
        /// <param name="protocol">Protocol to use: "tcp" or "udp" (default: "tcp")</param>
        /// <returns>True if port is open/responding, false otherwise</returns>
        public static async Task<bool> IsPortOpenAsync(
            string host, 
            int port, 
            int timeoutMs = 2000,
            string protocol = "tcp")
        {
            try
            {
                protocol = protocol.ToLower();
                if (protocol == "udp")
                {
                    return await IsUdpPortOpenAsync(host, port, timeoutMs);
                }
                else if (protocol == "tcp")
                {
                    return await IsTcpPortOpenAsync(host, port, timeoutMs);
                }
                else
                {
                    Log.Warning("Unknown protocol: {Protocol}, defaulting to TCP", protocol);
                    return await IsTcpPortOpenAsync(host, port, timeoutMs);
                }
            }
            catch (Exception ex)
            {
                Log.Debug("Port check failed for {Host}:{Port} ({Protocol}): {Error}", 
                    host, port, protocol, ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Check if a TCP port is open
        /// </summary>
        private static async Task<bool> IsTcpPortOpenAsync(string host, int port, int timeoutMs)
        {
            using var client = new TcpClient();
            using var cts = new CancellationTokenSource(timeoutMs);
            
            try
            {
                await client.ConnectAsync(host, port, cts.Token);
                return client.Connected;
            }
            catch (OperationCanceledException)
            {
                // Timeout
                return false;
            }
            catch (SocketException)
            {
                // Connection refused or other socket error
                return false;
            }
        }

        /// <summary>
        /// Check if a UDP port is open (best effort - UDP is connectionless)
        /// Sends a probe packet and waits for response or ICMP error
        /// </summary>
        private static async Task<bool> IsUdpPortOpenAsync(string host, int port, int timeoutMs)
        {
            using var client = new UdpClient();
            client.Client.ReceiveTimeout = timeoutMs;
            client.Client.SendTimeout = timeoutMs;
            
            try
            {
                // Connect to remote endpoint
                client.Connect(host, port);
                
                // Send probe packet (empty or protocol-specific)
                byte[] probeData = GetUdpProbeData(port);
                await client.SendAsync(probeData, probeData.Length);
                
                // Try to receive response (with timeout)
                using var cts = new CancellationTokenSource(timeoutMs);
                var receiveTask = client.ReceiveAsync(cts.Token);
                
                var result = await receiveTask;
                
                // If we got a response, port is open
                return result.Buffer.Length > 0;
            }
            catch (SocketException ex)
            {
                // ICMP Port Unreachable (ConnectionReset) = port closed
                if (ex.SocketErrorCode == SocketError.ConnectionReset)
                {
                    return false;
                }
                
                // Timeout or no response = possibly open (UDP is unreliable)
                // Return false by default to avoid false positives
                return false;
            }
            catch (OperationCanceledException)
            {
                // Timeout - can't determine definitively for UDP
                return false;
            }
        }

        /// <summary>
        /// Get protocol-specific UDP probe data
        /// </summary>
        private static byte[] GetUdpProbeData(int port)
        {
            // SNMP (161) - SNMPv1 GetRequest
            if (port == 161)
            {
                return new byte[] 
                { 
                    0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 
                    0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02 
                };
            }
            
            // DNS (53) - DNS query for example.com
            if (port == 53)
            {
                return new byte[]
                {
                    0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
                    0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
                    0x00, 0x00, 0x01, 0x00, 0x01
                };
            }
            
            // Default: empty packet
            return Array.Empty<byte>();
        }

        /// <summary>
        /// Get service banner from a TCP port
        /// Useful for identifying running services
        /// </summary>
        /// <param name="host">Target hostname or IP</param>
        /// <param name="port">Port number</param>
        /// <param name="timeoutMs">Timeout in milliseconds</param>
        /// <returns>Banner string or null if unavailable</returns>
        public static async Task<string?> GetBannerAsync(
            string host, 
            int port, 
            int timeoutMs = 5000)
        {
            try
            {
                using var client = new TcpClient();
                using var cts = new CancellationTokenSource(timeoutMs);
                
                await client.ConnectAsync(host, port, cts.Token);
                
                if (!client.Connected)
                    return null;

                using var stream = client.GetStream();
                stream.ReadTimeout = timeoutMs;
                
                // Some services send banner immediately (FTP, SMTP, SSH)
                var buffer = new byte[4096];
                var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cts.Token);
                
                if (bytesRead > 0)
                {
                    var banner = Encoding.UTF8.GetString(buffer, 0, bytesRead).Trim();
                    Log.Debug("Banner from {Host}:{Port} - {Banner}", host, port, banner);
                    return banner;
                }
                
                return null;
            }
            catch (Exception ex)
            {
                Log.Debug("Failed to get banner from {Host}:{Port}: {Error}", host, port, ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Ping a host to check if it's alive
        /// Uses ICMP echo request
        /// </summary>
        /// <param name="host">Target hostname or IP</param>
        /// <param name="timeoutMs">Timeout in milliseconds</param>
        /// <returns>True if host responds to ping</returns>
        public static async Task<bool> PingHostAsync(string host, int timeoutMs = 1000)
        {
            try
            {
                using var ping = new System.Net.NetworkInformation.Ping();
                var reply = await ping.SendPingAsync(host, timeoutMs);
                
                return reply.Status == System.Net.NetworkInformation.IPStatus.Success;
            }
            catch (Exception ex)
            {
                Log.Debug("Ping failed for {Host}: {Error}", host, ex.Message);
                return false;
            }
        }

        #endregion

        #region DNS & Hostname Utilities

        /// <summary>
        /// Resolve hostname to IP address
        /// </summary>
        /// <param name="hostname">Hostname to resolve</param>
        /// <returns>IP address string or null if resolution fails</returns>
        public static async Task<string?> ResolveHostnameAsync(string hostname)
        {
            try
            {
                var addresses = await Dns.GetHostAddressesAsync(hostname);
                
                if (addresses.Length > 0)
                {
                    // Prefer IPv4
                    var ipv4 = Array.Find(addresses, addr => addr.AddressFamily == AddressFamily.InterNetwork);
                    if (ipv4 != null)
                    {
                        Log.Debug("Resolved {Hostname} to {IP}", hostname, ipv4);
                        return ipv4.ToString();
                    }
                    
                    // Fallback to first address (might be IPv6)
                    Log.Debug("Resolved {Hostname} to {IP}", hostname, addresses[0]);
                    return addresses[0].ToString();
                }
                
                return null;
            }
            catch (Exception ex)
            {
                Log.Debug("Failed to resolve {Hostname}: {Error}", hostname, ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Check if a string is a valid IP address
        /// </summary>
        public static bool IsValidIpAddress(string input)
        {
            return IPAddress.TryParse(input, out _);
        }

        /// <summary>
        /// Check if a string is a valid hostname
        /// Basic validation - checks for valid characters
        /// </summary>
        public static bool IsValidHostname(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;
            
            // Basic hostname validation
            // Valid: letters, numbers, hyphens, dots
            // Must start with letter or number
            // Must end with letter or number
            return System.Text.RegularExpressions.Regex.IsMatch(
                input, 
                @"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$"
            );
        }

        /// <summary>
        /// Get local IP addresses of the machine
        /// </summary>
        public static async Task<List<string>> GetLocalIpAddressesAsync()
        {
            var localIps = new List<string>();
            
            try
            {
                var hostName = Dns.GetHostName();
                var addresses = await Dns.GetHostAddressesAsync(hostName);
                
                foreach (var address in addresses)
                {
                    // Skip loopback and IPv6 link-local
                    if (IPAddress.IsLoopback(address))
                        continue;
                    
                    if (address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        localIps.Add(address.ToString());
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Warning("Failed to get local IP addresses: {Error}", ex.Message);
            }
            
            return localIps;
        }

        /// <summary>
        /// Normalize domain/IP string for scanning
        /// Removes protocol, path, and port (if not needed)
        /// </summary>
        public static string NormalizeDomain(string input)
        {
            var normalized = input.Trim().ToLower();
            
            // Remove protocol
            if (normalized.Contains("://"))
            {
                normalized = new Uri(input).Host;
            }
            
            // Remove path
            if (normalized.Contains('/'))
            {
                normalized = normalized.Split('/')[0];
            }
            
            return normalized;
        }

        #endregion
    }
}