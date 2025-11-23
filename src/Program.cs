using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Serilog;

namespace Asterion
{
    /// <summary>
    /// Asterion Network Security Auditor - Entry Point
    /// The Minotaur of the Argos Suite
    /// 
    /// Cross-platform network, system, and domain auditor written in C# (.NET 8)
    /// Author: Rodney Dhavid Jimenez Chacin (rodhnin)
    /// License: MIT
    /// </summary>
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            // Initialize logger
            InitializeLogger();

            try
            {
                // Display banner
                DisplayBanner();

                // Detect platform
                DetectPlatform();

                // Parse CLI arguments and execute
                var cli = new Cli();
                return await cli.InvokeAsync(args);
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Fatal error in Asterion");
                Console.Error.WriteLine($"Fatal error: {ex.Message}");
                return 1;
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }

        private static void InitializeLogger()
        {
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Information()
                .WriteTo.Console(
                    outputTemplate: "[{Timestamp:HH:mm:ss}] [{Level:u3}] {Message:lj}{NewLine}{Exception}"
                )
                .WriteTo.File(
                    path: ExpandPath("~/.asterion/asterion.log"),
                    rollingInterval: RollingInterval.Day,
                    retainedFileCountLimit: 7
                )
                .CreateLogger();
        }

        private static void DisplayBanner()
        {
            try
            {
                // Try to load ASCII art from file
                var asciiPath = FindAsciiFile();
                
                if (asciiPath != null && File.Exists(asciiPath))
                {
                    var banner = File.ReadAllText(asciiPath);
                    Console.WriteLine(banner);
                }
                else
                {
                    // Fallback to simple banner if file not found
                    Console.WriteLine(@"
            ╔═══════════════════════════════════════════════════════════════╗
            ║                                                               ║
            ║              Network Security Auditor v0.1.0                  ║
            ║              The Minotaur of the Argos Suite                  ║
            ║                                                               ║
            ╚═══════════════════════════════════════════════════════════════╝
                    ");
                    Log.Debug("ASCII art file not found, using fallback banner");
                }
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Failed to load ASCII banner, using fallback");
                // Use fallback banner (same as above)
                Console.WriteLine("ASTERION - Network Security Auditor v0.1.0");
            }
            
            Console.WriteLine();
        }

        /// <summary>
        /// Find ASCII art file in multiple locations
        /// </summary>
        private static string? FindAsciiFile()
        {
            var locations = new[]
            {
                "assets/ascii.txt",
                "../../assets/ascii.txt",
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "assets", "ascii.txt"),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "assets", "ascii.txt")
            };

            foreach (var location in locations)
            {
                var fullPath = Path.GetFullPath(location);
                if (File.Exists(fullPath))
                {
                    Log.Debug("Found ASCII art at: {Path}", fullPath);
                    return fullPath;
                }
            }

            return null;
        }

        private static void DetectPlatform()
        {
            bool isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
            bool isLinux = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
            bool isMacOS = RuntimeInformation.IsOSPlatform(OSPlatform.OSX);

            string platform = isWindows ? "Windows" :
                             isLinux ? "Linux" :
                             isMacOS ? "macOS" :
                             "Unknown";

            string architecture = RuntimeInformation.OSArchitecture.ToString();

            Log.Information("Platform: {Platform} {Architecture}", platform, architecture);
            Log.Information("Runtime: {Framework}", RuntimeInformation.FrameworkDescription);
            
            Console.WriteLine($"Platform: {platform} {architecture}");
            Console.WriteLine($"Runtime: {RuntimeInformation.FrameworkDescription}");
            Console.WriteLine();
        }

        private static string ExpandPath(string path)
        {
            if (path.StartsWith("~/"))
            {
                string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                return path.Replace("~/", home + "/");
            }
            return path;
        }
    }
}