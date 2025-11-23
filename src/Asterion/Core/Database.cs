using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Serilog;
using Asterion.Models;

namespace Asterion.Core
{
    /// <summary>
    /// Database management for Asterion
    /// Handles SQLite operations for the shared Argos Suite database
    /// Location: ~/.argos/argos.db (shared with Argus, Hephaestus, Pythia)
    /// </summary>
    public class Database
    {
        private readonly string _connectionString;
        private readonly Config _config;

        public Database(Config config)
        {
            _config = config;
            _connectionString = $"Data Source={config.Paths.Database}";
            
            // Ensure database directory exists
            var dbDir = System.IO.Path.GetDirectoryName(config.Paths.Database);
            if (!string.IsNullOrEmpty(dbDir) && !System.IO.Directory.Exists(dbDir))
            {
                System.IO.Directory.CreateDirectory(dbDir);
            }
        }

        /// <summary>
        /// Determine scan status based on ScanResult
        /// Returns: "completed", "aborted", or "failed"
        /// </summary>
        private string DetermineStatus(Orchestrator.ScanResult result)
        {
            // SUCCESS = COMPLETED
            if (result.Success)
            {
                return "completed";
            }
            
            // NO SUCCESS + NO ERROR MESSAGE = FAILED
            if (string.IsNullOrEmpty(result.ErrorMessage))
            {
                Log.Warning("Scan failed with no error message - marking as 'failed'");
                return "failed";
            }
            
            // USER CANCELLED (Ctrl+C) = ABORTED
            var errorLower = result.ErrorMessage.ToLowerInvariant();
            
            if (errorLower.Contains("cancelled") || 
                errorLower.Contains("interrupted") || 
                errorLower.Contains("aborted"))
            {
                Log.Debug("Scan aborted by user: {Error}", result.ErrorMessage);
                return "aborted";
            }
            
            // VALIDATION ERROR = FAILED
            if (errorLower.Contains("no targets") ||
                errorLower.Contains("invalid") ||
                errorLower.Contains("consent") ||
                errorLower.Contains("rate limit"))
            {
                Log.Debug("Scan failed due to validation error: {Error}", result.ErrorMessage);
                return "failed";
            }
            
            // DEFAULT = FAILED
            Log.Debug("Scan failed: {Error}", result.ErrorMessage);
            return "failed";
        }

        /// <summary>
        /// Insert a scan record into the database
        /// Returns the scan_id of the inserted record
        /// </summary>
        public async Task<int> InsertScanAsync(
            Report report, 
            Orchestrator.ScanResult result,
            string? jsonPath = null, 
            string? htmlPath = null)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                
                // Build summary JSON
                var summaryJson = JsonSerializer.Serialize(new
                {
                    critical = report.Summary.Critical,
                    high = report.Summary.High,
                    medium = report.Summary.Medium,
                    low = report.Summary.Low,
                    info = report.Summary.Info
                });
                
                // Determine status dynamically
                string status = DetermineStatus(result);
                Log.Debug("Scan status determined: {Status}", status);
                
                var command = connection.CreateCommand();
                command.CommandText = @"
                    INSERT INTO scans (
                        tool, 
                        client_id, 
                        domain, 
                        target_url, 
                        mode, 
                        started_at, 
                        finished_at, 
                        status, 
                        report_json_path, 
                        report_html_path, 
                        summary,
                        error_message
                    ) VALUES (
                        @tool, 
                        NULL, 
                        @domain, 
                        @target_url, 
                        @mode, 
                        @started_at, 
                        @finished_at, 
                        @status, 
                        @report_json_path, 
                        @report_html_path, 
                        @summary,
                        @error_message
                    );
                    SELECT last_insert_rowid();
                ";
                
                command.Parameters.AddWithValue("@tool", report.Tool);
                command.Parameters.AddWithValue("@domain", ExtractDomain(report.Target));
                command.Parameters.AddWithValue("@target_url", report.Target);
                command.Parameters.AddWithValue("@mode", report.Mode);
                command.Parameters.AddWithValue("@started_at", report.Date);
                command.Parameters.AddWithValue("@finished_at", DateTime.UtcNow.ToString("o"));
                command.Parameters.AddWithValue("@status", status);
                command.Parameters.AddWithValue("@summary", summaryJson);
                command.Parameters.AddWithValue("@report_json_path", jsonPath ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@report_html_path", htmlPath ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@error_message", result.ErrorMessage ?? (object)DBNull.Value);
                
                var scanId = Convert.ToInt32(await command.ExecuteScalarAsync());
                Log.Information("Inserted scan record with ID: {ScanId}", scanId);
                
                // Insert findings
                foreach (var finding in report.Findings)
                {
                    await InsertFindingAsync(scanId, finding);
                }
                
                Log.Information("Inserted {Count} findings for scan {ScanId}", report.Findings.Count, scanId);
                
                return scanId;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to insert scan into database");
                throw;
            }
        }

        /// <summary>
        /// Insert a finding record into the database
        /// </summary>
        private async Task InsertFindingAsync(int scanId, Finding finding)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                // Serialize evidence and references to JSON
                var evidenceJson = finding.Evidence != null 
                    ? JsonSerializer.Serialize(finding.Evidence) 
                    : null;
                
                var referencesJson = finding.References != null && finding.References.Any()
                    ? JsonSerializer.Serialize(finding.References)
                    : null;

                var command = connection.CreateCommand();
                command.CommandText = @"
                    INSERT INTO findings (
                        scan_id,
                        finding_code,
                        title,
                        severity,
                        confidence,
                        evidence_type,
                        evidence_value,
                        recommendation,
                        ""references"",
                        created_at
                    ) VALUES (
                        @scan_id,
                        @finding_code,
                        @title,
                        @severity,
                        @confidence,
                        @evidence_type,
                        @evidence_value,
                        @recommendation,
                        @references,
                        @created_at
                    );
                ";
                
                command.Parameters.AddWithValue("@scan_id", scanId);
                command.Parameters.AddWithValue("@finding_code", finding.Id);
                command.Parameters.AddWithValue("@title", finding.Title);
                command.Parameters.AddWithValue("@severity", finding.Severity);
                command.Parameters.AddWithValue("@confidence", finding.Confidence);
                command.Parameters.AddWithValue("@evidence_type", 
                    finding.Evidence?.Type ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@evidence_value", evidenceJson ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@recommendation", finding.Recommendation);
                command.Parameters.AddWithValue("@references", referencesJson ?? (object)DBNull.Value);
                command.Parameters.AddWithValue("@created_at", DateTime.UtcNow.ToString("o"));
                
                await command.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to insert finding {FindingId}", finding.Id);
                throw;
            }
        }

        /// <summary>
        /// Get recent scans from the database
        /// </summary>
        public async Task<List<Dictionary<string, object>>> GetRecentScansAsync(int limit = 10)
        {
            var scans = new List<Dictionary<string, object>>();
            
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                
                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT * FROM v_recent_scans 
                    ORDER BY started_at DESC 
                    LIMIT @limit;
                ";
                command.Parameters.AddWithValue("@limit", limit);
                
                using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    var scan = new Dictionary<string, object>();
                    for (int i = 0; i < reader.FieldCount; i++)
                    {
                        scan[reader.GetName(i)] = reader.GetValue(i);
                    }
                    scans.Add(scan);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to get recent scans");
            }
            
            return scans;
        }

        /// <summary>
        /// Get critical findings from the database
        /// </summary>
        public async Task<List<Dictionary<string, object>>> GetCriticalFindingsAsync(int limit = 20)
        {
            var findings = new List<Dictionary<string, object>>();
            
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                
                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT * FROM v_critical_findings 
                    ORDER BY 
                        CASE severity 
                            WHEN 'critical' THEN 1 
                            WHEN 'high' THEN 2 
                        END,
                        started_at DESC 
                    LIMIT @limit;
                ";
                command.Parameters.AddWithValue("@limit", limit);
                
                using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    var finding = new Dictionary<string, object>();
                    for (int i = 0; i < reader.FieldCount; i++)
                    {
                        finding[reader.GetName(i)] = reader.GetValue(i);
                    }
                    findings.Add(finding);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to get critical findings");
            }
            
            return findings;
        }

        /// <summary>
        /// Get scan by ID with all findings
        /// </summary>
        public async Task<Dictionary<string, object>?> GetScanByIdAsync(int scanId)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                
                // Get scan info
                var scanCommand = connection.CreateCommand();
                scanCommand.CommandText = "SELECT * FROM scans WHERE scan_id = @scan_id;";
                scanCommand.Parameters.AddWithValue("@scan_id", scanId);
                
                Dictionary<string, object>? scan = null;
                using (var reader = await scanCommand.ExecuteReaderAsync())
                {
                    if (await reader.ReadAsync())
                    {
                        scan = new Dictionary<string, object>();
                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            scan[reader.GetName(i)] = reader.GetValue(i);
                        }
                    }
                }
                
                if (scan == null)
                {
                    return null;
                }
                
                // Get findings
                var findingsCommand = connection.CreateCommand();
                findingsCommand.CommandText = "SELECT * FROM findings WHERE scan_id = @scan_id;";
                findingsCommand.Parameters.AddWithValue("@scan_id", scanId);
                
                var findings = new List<Dictionary<string, object>>();
                using (var reader = await findingsCommand.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    {
                        var finding = new Dictionary<string, object>();
                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            finding[reader.GetName(i)] = reader.GetValue(i);
                        }
                        findings.Add(finding);
                    }
                }
                
                scan["findings"] = findings;
                return scan;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to get scan {ScanId}", scanId);
                return null;
            }
        }

        /// <summary>
        /// Extract domain from target URL
        /// </summary>
        private string ExtractDomain(string target)
        {
            try
            {
                if (target.Contains("://"))
                {
                    var uri = new Uri(target);
                    return uri.Host;
                }
                else if (target.Contains("/"))
                {
                    // CIDR notation
                    return target.Split('/')[0];
                }
                else
                {
                    return target;
                }
            }
            catch
            {
                return target;
            }
        }

        /// <summary>
        /// Get verified consent token for a domain (AUTOMATIC LOOKUP)
        /// Returns token string if valid and verified, null otherwise
        /// Validates: exists, verified, not expired, domain matches
        /// </summary>
        public async Task<string?> GetVerifiedConsentTokenAsync(string targetDomain)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                
                // Normalize domain for comparison
                var normalizedDomain = NormalizeDomain(targetDomain);
                
                Log.Debug("Looking for verified consent token for domain: {Domain}", normalizedDomain);
                
                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT token, expires_at, verified_at, domain
                    FROM consent_tokens 
                    WHERE LOWER(TRIM(domain)) = LOWER(TRIM(@domain))
                      AND verified_at IS NOT NULL
                      AND expires_at > @now
                    ORDER BY verified_at DESC
                    LIMIT 1;
                ";
                
                command.Parameters.AddWithValue("@domain", normalizedDomain);
                command.Parameters.AddWithValue("@now", DateTime.UtcNow.ToString("o"));
                
                using var reader = await command.ExecuteReaderAsync();
                if (await reader.ReadAsync())
                {
                    var token = reader.GetString(0);
                    var expiresAt = DateTime.Parse(reader.GetString(1));
                    var verifiedAt = DateTime.Parse(reader.GetString(2));
                    var storedDomain = reader.GetString(3);
                    
                    Log.Information("✓ Found verified consent token for {Domain}", storedDomain);
                    Log.Debug("  Token: {Token}", token);
                    Log.Debug("  Verified: {Verified}", verifiedAt.ToString("yyyy-MM-dd HH:mm:ss"));
                    Log.Debug("  Expires: {Expires}", expiresAt.ToString("yyyy-MM-dd HH:mm:ss"));
                    
                    return token;
                }
                
                Log.Debug("No verified consent token found for domain: {Domain}", normalizedDomain);
                return null;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to get verified consent token for domain: {Domain}", targetDomain);
                return null;
            }
        }

        /// <summary>
        /// Normalize domain for comparison (remove protocol, path, port, lowercase)
        /// </summary>
        private string NormalizeDomain(string domain)
        {
            if (string.IsNullOrEmpty(domain))
                return "";
            
            // Remove protocol
            if (domain.Contains("://"))
            {
                domain = new Uri(domain).Authority;
            }
            
            // Remove path
            if (domain.Contains('/'))
            {
                domain = domain.Split('/')[0];
            }
            
            // Remove port
            if (domain.Contains(':'))
            {
                domain = domain.Split(':')[0];
            }
            
            return domain.Trim().ToLower();
        }

        /// <summary>
        /// Get consent token from database by token string
        /// </summary>
        public async Task<Dictionary<string, object>?> GetConsentTokenAsync(string token)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                
                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT * FROM consent_tokens 
                    WHERE token = @token;
                ";
                command.Parameters.AddWithValue("@token", token);
                
                using var reader = await command.ExecuteReaderAsync();
                if (await reader.ReadAsync())
                {
                    var tokenData = new Dictionary<string, object>();
                    for (int i = 0; i < reader.FieldCount; i++)
                    {
                        tokenData[reader.GetName(i)] = reader.GetValue(i);
                    }
                    return tokenData;
                }
                
                return null;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to get consent token from database");
                return null;
            }
        }

        /// <summary>
        /// Insert consent token during generation (with method=NULL, pending verification)
        /// </summary>
        public async Task<int> InsertConsentTokenAsync(string domain, string token, DateTime expiresAt)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                
                var command = connection.CreateCommand();
                command.CommandText = @"
                    INSERT INTO consent_tokens (
                        domain, 
                        token, 
                        method,
                        created_at, 
                        verified_at,
                        proof_path,
                        expires_at
                    ) VALUES (
                        @domain, 
                        @token, 
                        NULL,
                        @created_at, 
                        NULL,
                        NULL,
                        @expires_at
                    );
                    SELECT last_insert_rowid();
                ";
                
                command.Parameters.AddWithValue("@domain", domain);
                command.Parameters.AddWithValue("@token", token);
                command.Parameters.AddWithValue("@created_at", DateTime.UtcNow.ToString("o"));
                command.Parameters.AddWithValue("@expires_at", expiresAt.ToString("o"));
                
                var tokenId = Convert.ToInt32(await command.ExecuteScalarAsync());
                Log.Information("Inserted consent token with ID: {TokenId} (pending verification)", tokenId);
                
                return tokenId;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to insert consent token into database");
                throw;
            }
        }

        /// <summary>
        /// Update consent token after successful verification
        /// Sets verified_at, method, and proof_path
        /// </summary>
        public async Task<bool> UpdateConsentTokenVerificationAsync(
            string token, 
            string method, 
            string proofPath)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                
                var command = connection.CreateCommand();
                command.CommandText = @"
                    UPDATE consent_tokens 
                    SET 
                        verified_at = @verified_at,
                        method = @method,
                        proof_path = @proof_path
                    WHERE token = @token;
                ";
                
                command.Parameters.AddWithValue("@verified_at", DateTime.UtcNow.ToString("o"));
                command.Parameters.AddWithValue("@method", method);
                command.Parameters.AddWithValue("@proof_path", proofPath);
                command.Parameters.AddWithValue("@token", token);
                
                var rowsAffected = await command.ExecuteNonQueryAsync();
                
                if (rowsAffected > 0)
                {
                    Log.Information("Updated consent token verification: {Token}", token);
                    return true;
                }
                else
                {
                    Log.Warning("Consent token not found in database: {Token}", token);
                    return false;
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to update consent token verification");
                throw;
            }
        }

        /// <summary>
        /// Check if a consent token is valid (exists, not expired, verified)
        /// </summary>
        public async Task<bool> IsConsentTokenValidAsync(string token)
        {
            try
            {
                var tokenData = await GetConsentTokenAsync(token);
                
                if (tokenData == null)
                {
                    Log.Debug("Consent token not found: {Token}", token);
                    return false;
                }
                
                // Check if verified
                if (tokenData["verified_at"] == DBNull.Value)
                {
                    Log.Debug("Consent token not verified: {Token}", token);
                    return false;
                }
                
                // Check if expired
                var expiresAtStr = tokenData["expires_at"]?.ToString();
                if (string.IsNullOrEmpty(expiresAtStr))
                {
                    Log.Warning("Consent token has no expiration: {Token}", token);
                    return false;
                }
                
                var expiresAt = DateTime.Parse(expiresAtStr);
                if (expiresAt < DateTime.UtcNow)
                {
                    Log.Debug("Consent token expired: {Token}", token);
                    return false;
                }
                
                return true;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to validate consent token");
                return false;
            }
        }
    }
}