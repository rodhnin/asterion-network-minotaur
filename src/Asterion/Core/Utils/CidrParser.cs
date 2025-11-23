using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Serilog;

namespace Asterion.Core.Utils
{
    /// <summary>
    /// CIDR notation parser and target expander
    /// Handles: single IPs, CIDR ranges, IP ranges, comma-separated lists
    /// </summary>
    public static class CidrParser
    {
        #region Public API - Main Entry Point
        
        /// <summary>
        /// Parse target string into list of targets
        /// Supports: single IP, CIDR range (/24), IP range (20-30), comma-separated list, domain name
        /// </summary>
        /// <param name="target">Target string to parse</param>
        /// <returns>List of individual target IPs/hostnames</returns>
        public static List<string> ParseTargets(string target)
        {
            var targets = new List<string>();
            
            // Handle comma-separated targets
            if (target.Contains(","))
            {
                var parts = target.Split(',', StringSplitOptions.RemoveEmptyEntries);
                foreach (var part in parts)
                {
                    targets.AddRange(ParseSingleTarget(part.Trim()));
                }
            }
            else
            {
                targets.AddRange(ParseSingleTarget(target.Trim()));
            }
            
            return targets.Distinct().ToList();
        }
        
        #endregion
        
        #region Private Parsing Logic
        
        /// <summary>
        /// Parse a single target (IP, CIDR, range, or hostname)
        /// </summary>
        private static List<string> ParseSingleTarget(string target)
        {
            var targets = new List<string>();
            
            // CIDR notation (192.168.100.0/24)
            if (target.Contains("/"))
            {
                targets.AddRange(ExpandCidr(target));
            }
            // IP range (192.168.100.20-30)
            else if (target.Contains("-") && IsIpRange(target))
            {
                targets.AddRange(ExpandRange(target));
            }
            // Single IP or hostname
            else
            {
                if (IsValidTarget(target))
                {
                    targets.Add(target);
                }
                else
                {
                    Log.Error("Invalid target: {Target} (not a valid IP address or hostname)", target);
                    
                    // Print error to user
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"\n✗ ERROR: Invalid target '{target}'");
                    Console.ResetColor();
                    
                    if (target.Contains('.') && target.Split('.').Length == 4)
                    {
                        // Looks like IP but invalid octets
                        Console.WriteLine("  IP addresses must have octets between 0-255");
                        Console.WriteLine("  Example: 192.168.1.1");
                    }
                    else
                    {
                        // Looks like hostname but invalid
                        Console.WriteLine("  Valid targets:");
                        Console.WriteLine("    • IP address: 192.168.1.1");
                        Console.WriteLine("    • CIDR range: 192.168.1.0/24");
                        Console.WriteLine("    • IP range: 192.168.1.10-20");
                        Console.WriteLine("    • IP Targets: 192.168.1.10,192.168.1.20");
                        Console.WriteLine("    • Hostname: example.com");
                    }
                    
                    // Return empty list to signal error
                }
            }
            
            return targets;
        }
        
        #endregion
        
        #region CIDR Expansion
        
        /// <summary>
        /// Expand CIDR notation to list of IPs (192.168.100.0/24 → 192.168.100.1-254)
        /// Handles special cases: /32 (single host), /31 (point-to-point)
        /// </summary>
        public static List<string> ExpandCidr(string cidr, bool includeNetworkAndBroadcast = false)
        {
            var targets = new List<string>();
            
            try
            {
                var parts = cidr.Split('/');
                if (parts.Length != 2)
                {
                    Log.Warning("Invalid CIDR format: {CIDR}, using as-is", cidr);
                    targets.Add(cidr);
                    return targets;
                }
                
                var baseIp = IPAddress.Parse(parts[0]);
                var prefixLength = int.Parse(parts[1]);
                
                if (prefixLength < 0 || prefixLength > 32)
                {
                    Log.Warning("Invalid CIDR prefix length: {Prefix}, must be 0-32", prefixLength);
                    targets.Add(cidr);
                    return targets;
                }
                
                // IPv4 only
                var ipBytes = baseIp.GetAddressBytes();
                if (ipBytes.Length != 4)
                {
                    Log.Warning("CIDR expansion only supports IPv4, got: {CIDR}", cidr);
                    targets.Add(cidr);
                    return targets;
                }
                
                // Convert to uint for bitwise operations
                Array.Reverse(ipBytes);
                uint ipUint = BitConverter.ToUInt32(ipBytes, 0);
                
                // Calculate network mask
                uint mask = prefixLength == 0 ? 0 : (0xffffffff << (32 - prefixLength));
                
                // Calculate network and broadcast addresses
                uint networkAddress = ipUint & mask;
                uint broadcastAddress = networkAddress | ~mask;
                
                // Special case: /32 (single host)
                if (prefixLength == 32)
                {
                    var bytes = BitConverter.GetBytes(networkAddress);
                    Array.Reverse(bytes);
                    targets.Add(new IPAddress(bytes).ToString());
                    Log.Debug("Expanded /32 CIDR {CIDR} to 1 IP address", cidr);
                    return targets;
                }
                
                // Special case: /31 (point-to-point link, RFC 3021)
                if (prefixLength == 31)
                {
                    for (uint i = networkAddress; i <= broadcastAddress; i++)
                    {
                        var bytes = BitConverter.GetBytes(i);
                        Array.Reverse(bytes);
                        targets.Add(new IPAddress(bytes).ToString());
                    }
                    Log.Debug("Expanded /31 CIDR {CIDR} to 2 IP addresses", cidr);
                    return targets;
                }
                
                // Normal case: /0 to /30
                uint startIp = includeNetworkAndBroadcast ? networkAddress : networkAddress + 1;
                uint endIp = includeNetworkAndBroadcast ? broadcastAddress : broadcastAddress - 1;
                
                // Sanity check (prevents uint underflow)
                if (endIp < startIp)
                {
                    Log.Warning("CIDR {CIDR} has no usable host addresses (too small range)", cidr);
                    return targets;
                }
                
                uint totalHosts = endIp - startIp + 1;
                
                // Warn for large ranges
                if (totalHosts > 100)
                {
                    Log.Warning("CIDR range {CIDR} expands to {Count} hosts, which is very large. Consider smaller ranges.", 
                        cidr, totalHosts);
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"\n⚠ WARNING: CIDR {cidr} expands to {totalHosts:N0} hosts");
                    Console.WriteLine("  This scan may take a very long time.");
                    Console.ResetColor();
                    Console.Write("  Continue? (y/N): ");
                    var response = Console.ReadLine()?.Trim().ToLowerInvariant();
                    if (response != "y" && response != "yes")
                    {
                        Log.Information("User cancelled large CIDR scan");
                        return targets; // Empty list = cancellation
                    }
                }
                
                // Generate IPs
                for (uint i = startIp; i <= endIp; i++)
                {
                    var bytes = BitConverter.GetBytes(i);
                    Array.Reverse(bytes);
                    targets.Add(new IPAddress(bytes).ToString());
                }
                
                Log.Information("Expanded CIDR {CIDR} to {Count} target(s)", cidr, targets.Count);
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Failed to parse CIDR {CIDR}, using as-is", cidr);
                targets.Add(cidr);
            }
            
            return targets;
        }
        
        #endregion
        
        #region IP Range Expansion
        
        /// <summary>
        /// Expand IP range to list (192.168.100.20-30 → 192.168.100.20...30)
        /// </summary>
        public static List<string> ExpandRange(string range)
        {
            var targets = new List<string>();
            
            try
            {
                var parts = range.Split('-');
                if (parts.Length != 2)
                {
                    Log.Warning("Invalid IP range format: {Range}, using as-is", range);
                    targets.Add(range);
                    return targets;
                }
                
                var baseIp = parts[0].Trim();
                var endOctet = int.Parse(parts[1].Trim());
                
                var ipParts = baseIp.Split('.');
                if (ipParts.Length != 4)
                {
                    Log.Warning("Invalid IP format in range: {IP}", baseIp);
                    targets.Add(range);
                    return targets;
                }
                
                var startOctet = int.Parse(ipParts[3]);
                
                if (startOctet < 0 || startOctet > 255 || endOctet < 0 || endOctet > 255)
                {
                    Log.Warning("Invalid octet range: {Start}-{End}, must be 0-255", startOctet, endOctet);
                    targets.Add(range);
                    return targets;
                }
                
                if (endOctet < startOctet)
                {
                    Log.Warning("Invalid range {Range}: end octet must be >= start octet", range);
                    targets.Add(range);
                    return targets;
                }
                
                // Generate IPs
                for (int i = startOctet; i <= endOctet; i++)
                {
                    targets.Add($"{ipParts[0]}.{ipParts[1]}.{ipParts[2]}.{i}");
                }
                
                Log.Information("Expanded range {Range} to {Count} target(s)", range, targets.Count);
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Failed to parse range {Range}, using as-is", range);
                targets.Add(range);
            }
            
            return targets;
        }
        
        #endregion
        
        #region Validation Helpers
        
        /// <summary>
        /// Check if string is valid CIDR notation
        /// </summary>
        public static bool IsValidCidr(string input)
        {
            try
            {
                var parts = input.Split('/');
                if (parts.Length != 2) return false;
                if (!IPAddress.TryParse(parts[0], out _)) return false;
                if (!int.TryParse(parts[1], out var prefix)) return false;
                return prefix >= 0 && prefix <= 32;
            }
            catch
            {
                return false;
            }
        }
        
        /// <summary>
        /// Check if string looks like an IP range (192.168.100.20-30)
        /// </summary>
        public static bool IsIpRange(string input)
        {
            try
            {
                var parts = input.Split('-');
                if (parts.Length != 2) return false;
                
                var firstPart = parts[0].Trim();
                var secondPart = parts[1].Trim();
                
                // First part must be valid IP
                if (!IPAddress.TryParse(firstPart, out _)) return false;
                
                // Second part must be just a number (last octet)
                if (!int.TryParse(secondPart, out int endOctet)) return false;
                
                return endOctet >= 0 && endOctet <= 255;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Validate if target is a valid IP address or hostname
        /// </summary>
        /// <param name="target">Target string to validate</param>
        /// <returns>True if valid IP or hostname</returns>
        private static bool IsValidTarget(string target)
        {
            if (string.IsNullOrWhiteSpace(target))
                return false;
            
            bool looksLikeIp = target.Contains('.') && 
                            target.Split('.').Length == 4 && 
                            target.Split('.').All(part => part.All(char.IsDigit));
            
            if (looksLikeIp)
            {
                // Input looks like an IP (4 numeric parts), validate strictly as IP
                if (!IPAddress.TryParse(target, out var ip))
                {
                    Log.Debug("Invalid IP format: {Target}", target);
                    return false;
                }
                
                // Additional validation: ensure each octet is 0-255
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    var octets = target.Split('.');
                    
                    foreach (var octet in octets)
                    {
                        // Check for leading zeros (010 is invalid, but 10 or 0 is valid)
                        if (octet.Length > 1 && octet[0] == '0')
                        {
                            Log.Debug("Invalid IP octet with leading zero: {Octet} in {Target}", octet, target);
                            return false;
                        }
                        
                        if (!int.TryParse(octet, out int value))
                            return false;
                        
                        if (value < 0 || value > 255)
                        {
                            Log.Debug("Invalid IP octet out of range: {Octet} (must be 0-255) in {Target}", octet, target);
                            return false;
                        }
                    }
                    
                    return true;
                }
                
                // IPv6 (future support)
                return true;
            }
            
            // NOT an IP-looking string, validate as hostname
            return IsValidHostname(target);
        }

        /// <summary>
        /// Check if string is a valid hostname
        /// Basic validation - checks for valid characters
        /// </summary>
        /// <param name="input">Hostname to validate</param>
        /// <returns>True if valid hostname format</returns>
        private static bool IsValidHostname(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;
            
            // Hostname validation rules:
            // - Letters, numbers, hyphens, dots
            // - Must start with letter or number
            // - Must end with letter or number
            // - Max 253 chars total, max 63 per label
            // - No consecutive dots
            
            if (input.Length > 253)
                return false;
            
            if (input.Contains(".."))
                return false;
            
            // Split by dots and validate each label
            var labels = input.Split('.');
            foreach (var label in labels)
            {
                if (string.IsNullOrWhiteSpace(label))
                    return false;
                
                if (label.Length > 63)
                    return false;
                
                // Must start/end with alphanumeric
                if (!char.IsLetterOrDigit(label[0]))
                    return false;
                
                if (!char.IsLetterOrDigit(label[^1]))
                    return false;
                
                // Only letters, numbers, and hyphens allowed
                foreach (var c in label)
                {
                    if (!char.IsLetterOrDigit(c) && c != '-')
                        return false;
                }
            }
            
            return true;
        }
        
        #endregion
        
        #region Network Address Helpers
        
        /// <summary>
        /// Get network address from CIDR
        /// </summary>
        public static string GetNetworkAddress(string cidr)
        {
            try
            {
                var parts = cidr.Split('/');
                var baseIp = IPAddress.Parse(parts[0]);
                var prefixLength = int.Parse(parts[1]);
                
                var baseIpBytes = baseIp.GetAddressBytes();
                Array.Reverse(baseIpBytes);
                var baseIpUint = BitConverter.ToUInt32(baseIpBytes, 0);
                
                var mask = 0xffffffff << (32 - prefixLength);
                var networkAddress = baseIpUint & mask;
                
                var networkBytes = BitConverter.GetBytes(networkAddress);
                Array.Reverse(networkBytes);
                return new IPAddress(networkBytes).ToString();
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to get network address from: {CIDR}", cidr);
                return cidr;
            }
        }
        
        /// <summary>
        /// Get broadcast address from CIDR
        /// </summary>
        public static string GetBroadcastAddress(string cidr)
        {
            try
            {
                var parts = cidr.Split('/');
                var baseIp = IPAddress.Parse(parts[0]);
                var prefixLength = int.Parse(parts[1]);
                
                var baseIpBytes = baseIp.GetAddressBytes();
                Array.Reverse(baseIpBytes);
                var baseIpUint = BitConverter.ToUInt32(baseIpBytes, 0);
                
                var mask = 0xffffffff << (32 - prefixLength);
                var networkAddress = baseIpUint & mask;
                var broadcastAddress = networkAddress | ~mask;
                
                var broadcastBytes = BitConverter.GetBytes(broadcastAddress);
                Array.Reverse(broadcastBytes);
                return new IPAddress(broadcastBytes).ToString();
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to get broadcast address from: {CIDR}", cidr);
                return cidr;
            }
        }
        
        #endregion
    }
}