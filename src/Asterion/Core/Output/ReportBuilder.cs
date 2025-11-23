using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading.Tasks;
using Serilog;
using Asterion.Models;

namespace Asterion.Core.Output
{
    /// <summary>
    /// Report Builder for Asterion
    /// Generates structured reports in JSON and HTML formats
    /// </summary>
    public class ReportBuilder
    {
        private readonly Config _config;

        public ReportBuilder(Config config)
        {
            _config = config;
        }

        /// <summary>
        /// Build a structured report dictionary
        /// </summary>
        public Report BuildReport(
            string tool,
            string version,
            string target,
            string mode,
            List<Finding> findings,
            FindingSummary summary,
            double scanDuration,
            int requestsSent,
            ConsentInfo? consent = null,
            AiAnalysis? aiAnalysis = null)
        {
            var report = new Report
            {
                Tool = tool,
                Version = version,
                Target = target,
                Date = DateTime.UtcNow.ToString("o"),
                Mode = mode,
                Summary = summary,
                Findings = findings,
                Notes = new ReportNotes
                {
                    ScanDurationSeconds = Math.Round(scanDuration, 2),
                    RequestsSent = requestsSent,
                    RateLimitApplied = true,
                    FalsePositiveDisclaimer = "Manual verification recommended for all findings before remediation."
                }
            };

            if (consent != null)
            {
                report.Consent = consent;
            }

            if (aiAnalysis != null)
            {
                report.AiAnalysis = aiAnalysis;
            }

            return report;
        }

        /// <summary>
        /// Save report as JSON file
        /// </summary>
        public async Task<string> SaveJsonAsync(Report report, string target)
        {
            try
            {
                // Generate filename
                var targetClean = target.Replace("://", "_").Replace("/", "_").Replace(":", "_");
                var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
                var filename = $"{report.Tool}_report_{targetClean}_{timestamp}.json";
                var outputPath = Path.Combine(_config.Paths.ReportDir, filename);

                // Ensure directory exists
                Directory.CreateDirectory(_config.Paths.ReportDir);

                // Serialize with pretty printing
                var options = new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    WriteIndented = true,
                    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
                };

                var json = JsonSerializer.Serialize(report, options);
                await File.WriteAllTextAsync(outputPath, json);

                Log.Information("JSON report saved: {Path}", outputPath);
                return outputPath;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to save JSON report");
                throw;
            }
        }

        /// <summary>
        /// Generate HTML report from JSON using Python Jinja2 renderer
        /// Falls back to basic C# rendering if Python is unavailable
        /// </summary>
        public async Task<string> SaveHtmlAsync(Report report, string target)
        {
            try
            {
                // Generate filename matching JSON
                var targetClean = target.Replace("://", "_").Replace("/", "_").Replace(":", "_");
                var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
                var filename = $"{report.Tool}_report_{targetClean}_{timestamp}.html";
                var outputPath = Path.Combine(_config.Paths.ReportDir, filename);

                // Ensure directory exists
                Directory.CreateDirectory(_config.Paths.ReportDir);

                // First, save the report as JSON (needed for Python renderer)
                var tempJsonPath = Path.Combine(_config.Paths.ReportDir, $"temp_{filename}.json");
                var options = new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    WriteIndented = true,
                    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
                };
                await File.WriteAllTextAsync(tempJsonPath, JsonSerializer.Serialize(report, options));

                // Try Python renderer first (preferred - full Jinja2 support)
                bool pythonSuccess = await RenderHtmlWithPython(tempJsonPath, outputPath);

                if (!pythonSuccess)
                {
                    // Fallback to basic C# rendering
                    Log.Warning("Python renderer failed, falling back to basic C# HTML rendering");
                    await RenderHtmlBasic(report, outputPath);
                }

                // Clean up temp JSON
                try
                {
                    File.Delete(tempJsonPath);
                }
                catch
                {
                    // Ignore cleanup errors
                }

                Log.Information("HTML report saved: {Path}", outputPath);
                return outputPath;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to save HTML report");
                throw;
            }
        }

        /// <summary>
        /// Render HTML using Python Jinja2 renderer (full template support)
        /// </summary>
        private async Task<bool> RenderHtmlWithPython(string jsonPath, string htmlPath)
        {
            try
            {
                // Locate Python renderer script
                var scriptPath = FindPythonRenderer();
                if (scriptPath == null)
                {
                    Log.Warning("Python HTML renderer script not found (render_html.py)");
                    return false;
                }

                Log.Debug("Using Python renderer: {Script}", scriptPath);

                // Locate template
                var templatePath = FindTemplate();
                if (templatePath == null)
                {
                    Log.Warning("HTML template not found (report.html.j2)");
                    return false;
                }

                // Prepare arguments
                var args = $"\"{scriptPath}\" --input \"{jsonPath}\" --template \"{templatePath}\" --output \"{htmlPath}\"";

                // Invoke Python
                // Use 'python' on Windows, 'python3' on Linux/Mac
                var pythonCmd = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "python" : "python3";

                var processInfo = new ProcessStartInfo
                {
                    FileName = pythonCmd,
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(processInfo);
                if (process == null)
                {
                    Log.Warning("Failed to start Python process");
                    return false;
                }

                var output = await process.StandardOutput.ReadToEndAsync();
                var error = await process.StandardError.ReadToEndAsync();
                await process.WaitForExitAsync();

                if (process.ExitCode != 0)
                {
                    Log.Warning("Python renderer failed with exit code {Code}: {Error}", process.ExitCode, error);
                    return false;
                }
                Log.Debug("HTML rendered successfully with Python Jinja2");
                return true;
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Failed to invoke Python HTML renderer");
                return false;
            }
        }

        /// <summary>
        /// Basic HTML rendering fallback (limited template support)
        /// </summary>
        private async Task RenderHtmlBasic(Report report, string outputPath)
        {
            try
            {
                // Load template
                var templatePath = FindTemplate();
                if (templatePath == null)
                {
                    throw new FileNotFoundException("HTML template not found: report.html.j2");
                }

                var template = await File.ReadAllTextAsync(templatePath);

                Log.Warning("Using basic C# HTML rendering - Jinja2 features will not work properly");
                Log.Warning("Install Python dependencies (pip install jinja2 markdown) for full rendering");

                // Simple template rendering (very limited)
                var html = template
                    .Replace("{{ report.tool }}", report.Tool)
                    .Replace("{{ report.version }}", report.Version)
                    .Replace("{{ report.target }}", report.Target)
                    .Replace("{{ report.date }}", report.Date)
                    .Replace("{{ report.mode }}", report.Mode)
                    .Replace("{{ report.summary.critical }}", report.Summary.Critical.ToString())
                    .Replace("{{ report.summary.high }}", report.Summary.High.ToString())
                    .Replace("{{ report.summary.medium }}", report.Summary.Medium.ToString())
                    .Replace("{{ report.summary.low }}", report.Summary.Low.ToString())
                    .Replace("{{ report.summary.info }}", report.Summary.Info.ToString());

                // Build findings HTML (very basic)
                var findingsHtml = string.Join("\n", report.Findings.Select(f => $@"
                    <div class='finding-card {f.Severity}'>
                        <h3>{f.Id}: {f.Title}</h3>
                        <p><strong>Severity:</strong> <span class='severity-badge {f.Severity}'>{f.Severity}</span></p>
                        <p><strong>Confidence:</strong> {f.Confidence}</p>
                        <p>{f.Description}</p>
                        <p><strong>Recommendation:</strong> {f.Recommendation}</p>
                    </div>
                "));

                // Remove Jinja2 syntax (won't work in basic rendering)
                html = System.Text.RegularExpressions.Regex.Replace(html, @"\{%.*?%\}", "");
                html = System.Text.RegularExpressions.Regex.Replace(html, @"\{\{.*?\}\}", "");
                html = html.Replace("<!-- FINDINGS_PLACEHOLDER -->", findingsHtml);

                await File.WriteAllTextAsync(outputPath, html);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Basic HTML rendering failed");
                throw;
            }
        }

        /// <summary>
        /// Find Python HTML renderer script
        /// </summary>
        private string? FindPythonRenderer()
        {
            var locations = new[]
            {
                "scripts/render_html.py",
                "../scripts/render_html.py",
                "../../scripts/render_html.py",
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "scripts", "render_html.py"),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "scripts", "render_html.py"),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "scripts", "render_html.py")
            };

            foreach (var location in locations)
            {
                var fullPath = Path.GetFullPath(location);
                if (File.Exists(fullPath))
                {
                    return fullPath;
                }
            }

            return null;
        }

        /// <summary>
        /// Find HTML template file
        /// </summary>
        private string? FindTemplate()
        {
            var locations = new[]
            {
                "templates/report.html.j2",
                "../templates/report.html.j2",
                "../../templates/report.html.j2",
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "templates", "report.html.j2"),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "templates", "report.html.j2"),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "templates", "report.html.j2")
            };

            foreach (var location in locations)
            {
                var fullPath = Path.GetFullPath(location);
                if (File.Exists(fullPath))
                {
                    return fullPath;
                }
            }

            return null;
        }

        /// <summary>
        /// Create a finding with proper structure
        /// </summary>
        public Finding CreateFinding(
            string findingId,
            string title,
            string severity,
            string confidence,
            string recommendation,
            string? description = null,
            Evidence? evidence = null,
            List<string>? references = null,
            List<string>? cve = null,
            string? affectedComponent = null)
        {
            return new Finding
            {
                Id = findingId,
                Title = title,
                Severity = severity,
                Confidence = confidence,
                Recommendation = recommendation,
                Description = description,
                Evidence = evidence,
                References = references,
                Cve = cve,
                AffectedComponent = affectedComponent
            };
        }
    }
}