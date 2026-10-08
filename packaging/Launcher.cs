using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

[assembly: AssemblyTitle("ClaudeGuard")]
[assembly: AssemblyProduct("ClaudeGuard")]
[assembly: AssemblyDescription("ClaudeGuard Windows x64 launcher")]
[assembly: AssemblyVersion("1.0.3.0")]
[assembly: AssemblyFileVersion("1.0.3.0")]

internal sealed class BundleManifest
{
    public string version { get; set; }
    public string assemblyVersion { get; set; }
    public string payloadSha256 { get; set; }
    public List<ManifestFile> files { get; set; }
}

internal sealed class ManifestFile
{
    public string path { get; set; }
    public long length { get; set; }
    public string sha256 { get; set; }
}

internal sealed class Bundle
{
    public byte[] ZipBytes;
    public BundleManifest Manifest;
    public string PayloadSha256;
}

internal sealed class LaunchOptions
{
    public bool VerifyOnly;
    public bool ExtractOnly;
    public bool Reconfigure;
    public string Destination;
    public string Receipt;
}

internal static class Program
{
    private const string Version = "1.0.3";
    private const string AssemblyVersionText = "1.0.3.0";
    private const string MutexName = "Local\\ClaudeGuard-Launcher-1.0.3";
    private static readonly JavaScriptSerializer Serializer = new JavaScriptSerializer();

    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            return Run(args ?? new string[0]);
        }
        catch (Exception ex)
        {
            if (!HasInspectionOption(args)) ShowError(ex.Message);
            return 1;
        }
    }

    private static bool HasInspectionOption(string[] args)
    {
        if (args == null) return false;
        foreach (string arg in args)
        {
            if (String.Equals(arg, "--verify-only", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(arg, "--extract-only", StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }
    private static int Run(string[] args)
    {
        LaunchOptions options = ParseOptions(args);
        if (options.VerifyOnly || options.ExtractOnly)
        {
            return RunInspection(options);
        }
        return RunLaunch(options.Reconfigure, options.Destination);
    }

    private static LaunchOptions ParseOptions(string[] args)
    {
        LaunchOptions options = new LaunchOptions();
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i] ?? String.Empty;
            if (String.Equals(arg, "--verify-only", StringComparison.OrdinalIgnoreCase))
            {
                options.VerifyOnly = true;
            }
            else if (String.Equals(arg, "--extract-only", StringComparison.OrdinalIgnoreCase))
            {
                options.ExtractOnly = true;
            }
            else if (String.Equals(arg, "--reconfigure", StringComparison.OrdinalIgnoreCase))
            {
                options.Reconfigure = true;
            }
            else if (String.Equals(arg, "--destination", StringComparison.OrdinalIgnoreCase))
            {
                options.Destination = RequireValue(args, ref i, "--destination");
            }
            else if (String.Equals(arg, "--receipt", StringComparison.OrdinalIgnoreCase))
            {
                options.Receipt = RequireValue(args, ref i, "--receipt");
            }
            else
            {
                throw new ArgumentException("Unknown option: " + arg);
            }
        }
        if (options.VerifyOnly && options.ExtractOnly)
        {
            throw new ArgumentException("--verify-only and --extract-only cannot be combined.");
        }
        if (options.Reconfigure && (options.VerifyOnly || options.ExtractOnly))
        {
            throw new ArgumentException("--reconfigure is only valid for a normal launch.");
        }
        if (options.ExtractOnly && String.IsNullOrWhiteSpace(options.Destination))
        {
            throw new ArgumentException("--extract-only requires --destination <path>.");
        }
        return options;
    }

    private static string RequireValue(string[] args, ref int index, string option)
    {
        if (index + 1 >= args.Length || String.IsNullOrEmpty(args[index + 1]))
        {
            throw new ArgumentException(option + " requires a value.");
        }
        index++;
        return args[index];
    }

    private static int RunInspection(LaunchOptions options)
    {
        try
        {
            Bundle bundle = LoadBundle();
            Dictionary<string, object> receipt = CreateReceipt(options.VerifyOnly ? "verify-only" : "extract-only", bundle);
            receipt["status"] = "success";
            receipt["codeVerified"] = true;
            if (options.VerifyOnly)
            {
                receipt["extracted"] = false;
            }
            else
            {
                string destination = Path.GetFullPath(options.Destination);
                ExtractVerified(bundle, destination);
                receipt["destination"] = destination;
                receipt["extracted"] = true;
            }
            WriteReceipt(options.Receipt, receipt);
            return 0;
        }
        catch (Exception ex)
        {
            WriteFailureReceipt(options.Receipt, options.ExtractOnly ? "extract-only" : "verify-only", ex);
            throw;
        }
    }

    private static int RunLaunch(bool reconfigure, string destinationOverride)
    {
        Bundle bundle = LoadBundle();
        using (Mutex mutex = new Mutex(false, MutexName))
        {
            bool ownsMutex = false;
            try
            {
                try
                {
                    ownsMutex = mutex.WaitOne(0);
                }
                catch (AbandonedMutexException)
                {
                    ownsMutex = true;
                }
                if (!ownsMutex && reconfigure)
                {
                    try
                    {
                        ownsMutex = mutex.WaitOne(TimeSpan.FromSeconds(5));
                    }
                    catch (AbandonedMutexException)
                    {
                        ownsMutex = true;
                    }
                }
                if (!ownsMutex)
                {
                    throw new InvalidOperationException(reconfigure
                        ? "ClaudeGuard is still closing. Try reconfigure again in a moment."
                        : "ClaudeGuard is already running.");
                }

                string appDirectory = String.IsNullOrWhiteSpace(destinationOverride) ? GetVersionDirectory(bundle.PayloadSha256) : Path.GetFullPath(destinationOverride);
                ExtractVerified(bundle, appDirectory);
                CopyLauncherIntoAppDirectory(appDirectory);
                string script = Path.Combine(appDirectory, "ClaudeGuardUI.ps1");
                if (!File.Exists(script))
                {
                    throw new InvalidDataException("Verified payload does not contain ClaudeGuardUI.ps1.");
                }
                return StartPowerShell(script, appDirectory, reconfigure);
            }
            finally
            {
                if (ownsMutex)
                {
                    try { mutex.ReleaseMutex(); } catch (ApplicationException) { }
                }
            }
        }
    }

    private static int StartPowerShell(string script, string workingDirectory, bool reconfigure)
    {
        string systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.System);
        string powershell = Path.Combine(systemRoot, "WindowsPowerShell\\v1.0\\powershell.exe");
        if (!File.Exists(powershell))
        {
            throw new FileNotFoundException("Windows PowerShell 5.1 was not found.", powershell);
        }
        StringBuilder arguments = new StringBuilder();
        arguments.Append("-NoProfile -STA -File ");
        arguments.Append(QuoteArgument(script));
        if (reconfigure)
        {
            arguments.Append(" -Reconfigure");
        }
        ProcessStartInfo startInfo = new ProcessStartInfo(powershell, arguments.ToString());
        startInfo.UseShellExecute = false;
        startInfo.CreateNoWindow = true;
        startInfo.WindowStyle = ProcessWindowStyle.Hidden;
        startInfo.WorkingDirectory = workingDirectory;
        string nativeModules = Path.Combine(systemRoot, "WindowsPowerShell\\v1.0\\Modules");
        string userModules = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "WindowsPowerShell\\Modules");
        string sharedModules = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsPowerShell\\Modules");
        startInfo.EnvironmentVariables["PSModulePath"] = String.Join(Path.PathSeparator.ToString(), new string[] { nativeModules, userModules, sharedModules });
        using (Process child = Process.Start(startInfo))
        {
            child.WaitForExit();
            return child.ExitCode;
        }
    }

    private static string QuoteArgument(string value)
    {
        if (value.IndexOf('"') >= 0)
        {
            throw new ArgumentException("A payload path contains an unsupported quote character.");
        }
        return "\"" + value + "\"";
    }

    private static string GetVersionDirectory(string payloadHash)
    {
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (String.IsNullOrWhiteSpace(local)) throw new IOException("LocalApplicationData is unavailable.");
        string prefix = payloadHash.Substring(0, 12).ToLowerInvariant();
        return Path.Combine(Path.GetFullPath(local), "ClaudeGuard", "versions", Version + "-" + prefix);
    }

    private static void CopyLauncherIntoAppDirectory(string appDirectory)
    {
        string current;
        try
        {
            current = Process.GetCurrentProcess().MainModule.FileName;
        }
        catch
        {
            return;
        }
        if (String.IsNullOrWhiteSpace(current) || !File.Exists(current))
        {
            return;
        }
        string target = Path.Combine(appDirectory, "ClaudeGuard.exe");
        if (String.Equals(Path.GetFullPath(current), Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase))
        {
            return;
        }
        string temp = target + ".tmp-" + Guid.NewGuid().ToString("N");
        File.Copy(current, temp, true);
        try
        {
            if (File.Exists(target))
            {
                File.Replace(temp, target, null);
            }
            else
            {
                File.Move(temp, target);
            }
        }
        finally
        {
            if (File.Exists(temp))
            {
                try { File.Delete(temp); } catch { }
            }
        }
    }

    private static Bundle LoadBundle()
    {
        byte[] zipBytes = ReadResource("ClaudeGuard.Payload.zip");
        byte[] manifestBytes = ReadResource("ClaudeGuard.Payload.manifest.json");
        BundleManifest manifest = Serializer.Deserialize<BundleManifest>(Encoding.UTF8.GetString(manifestBytes));
        ValidateManifest(manifest);
        string payloadHash = HashBytes(zipBytes);
        if (!String.Equals(payloadHash, manifest.payloadSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Embedded payload hash does not match its manifest.");
        }
        VerifyZip(zipBytes, manifest);
        return new Bundle { ZipBytes = zipBytes, Manifest = manifest, PayloadSha256 = payloadHash };
    }

    private static byte[] ReadResource(string suffix)
    {
        Assembly assembly = typeof(Program).Assembly;
        string resourceName = null;
        foreach (string name in assembly.GetManifestResourceNames())
        {
            if (name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                if (resourceName != null)
                {
                    throw new InvalidDataException("Duplicate embedded resource: " + suffix);
                }
                resourceName = name;
            }
        }
        if (resourceName == null)
        {
            throw new InvalidDataException("Missing embedded resource: " + suffix);
        }
        using (Stream source = assembly.GetManifestResourceStream(resourceName))
        using (MemoryStream target = new MemoryStream())
        {
            source.CopyTo(target);
            return target.ToArray();
        }
    }

    private static void ValidateManifest(BundleManifest manifest)
    {
        if (manifest == null || !String.Equals(manifest.version, Version, StringComparison.Ordinal) ||
            !String.Equals(manifest.assemblyVersion, AssemblyVersionText, StringComparison.Ordinal) ||
            manifest.files == null || manifest.files.Count == 0 || manifest.files.Count > 96)
        {
            throw new InvalidDataException("Invalid ClaudeGuard payload manifest version.");
        }
        if (!IsSha256(manifest.payloadSha256))
        {
            throw new InvalidDataException("Invalid payload hash in manifest.");
        }
        Dictionary<string, ManifestFile> seen = new Dictionary<string, ManifestFile>(StringComparer.OrdinalIgnoreCase);
        foreach (ManifestFile file in manifest.files)
        {
            if (file == null || String.IsNullOrEmpty(file.path) || !IsSha256(file.sha256) || file.length < 0 || file.length > 20L * 1024 * 1024)
            {
                throw new InvalidDataException("Invalid file entry in payload manifest.");
            }
            string path = ValidateRelativePath(file.path);
            if (seen.ContainsKey(path))
            {
                throw new InvalidDataException("Duplicate payload path: " + path);
            }
            seen.Add(path, file);
        }
    }

    private static bool IsSha256(string value)
    {
        if (String.IsNullOrEmpty(value) || value.Length != 64) return false;
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
        }
        return true;
    }

    private static string ValidateRelativePath(string path)
    {
        if (String.IsNullOrEmpty(path) || path[0] == '/' || path[0] == '\\' || path.IndexOf('\\') >= 0 || path.IndexOf(':') >= 0)
        {
            throw new InvalidDataException("Unsafe payload path: " + path);
        }
        string[] parts = path.Split('/');
        foreach (string part in parts)
        {
            if (String.IsNullOrEmpty(part) || part == "." || part == ".." || part.IndexOf('\0') >= 0)
            {
                throw new InvalidDataException("Unsafe payload path: " + path);
            }
        }
        return path;
    }

    private static void VerifyZip(byte[] zipBytes, BundleManifest manifest)
    {
        Dictionary<string, ManifestFile> expected = new Dictionary<string, ManifestFile>(StringComparer.OrdinalIgnoreCase);
        foreach (ManifestFile file in manifest.files) expected.Add(file.path, file);
        HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (MemoryStream source = new MemoryStream(zipBytes))
        using (ZipArchive archive = new ZipArchive(source, ZipArchiveMode.Read, false))
        {
            foreach (ZipArchiveEntry entry in archive.Entries)
            {
                if (String.IsNullOrEmpty(entry.FullName) || entry.FullName.EndsWith("/", StringComparison.Ordinal))
                {
                    throw new InvalidDataException("Directory or empty entry in payload ZIP: " + entry.FullName);
                }
                string path = ValidateRelativePath(entry.FullName);
                if (!seen.Add(path))
                {
                    throw new InvalidDataException("Duplicate ZIP path: " + path);
                }
                ManifestFile file;
                if (!expected.TryGetValue(path, out file))
                {
                    throw new InvalidDataException("Unexpected ZIP path: " + path);
                }
                long length;
                string hash;
                using (Stream entryStream = entry.Open())
                {
                    hash = HashStream(entryStream, out length);
                }
                if (length != file.length || !String.Equals(hash, file.sha256, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("Payload file hash mismatch: " + path);
                }
            }
        }
        if (seen.Count != expected.Count)
        {
            throw new InvalidDataException("Payload ZIP is missing a manifest file.");
        }
    }

    private static void ExtractVerified(Bundle bundle, string destination)
    {
        string fullDestination = Path.GetFullPath(destination);
        string parent = Path.GetDirectoryName(fullDestination);
        if (String.IsNullOrEmpty(parent)) throw new InvalidDataException("Invalid extraction destination.");
        Directory.CreateDirectory(parent);
        if (File.Exists(fullDestination)) throw new IOException("Extraction destination is a file: " + fullDestination);
        if (Directory.Exists(fullDestination))
        {
            VerifyExisting(fullDestination, bundle.Manifest);
            return;
        }

        string stage = fullDestination + ".staging-" + Guid.NewGuid().ToString("N");
        Directory.CreateDirectory(stage);
        try
        {
            ExtractZip(bundle.ZipBytes, bundle.Manifest, stage);
            VerifyExisting(stage, bundle.Manifest);
            try
            {
                Directory.Move(stage, fullDestination);
            }
            catch (IOException)
            {
                if (!Directory.Exists(fullDestination)) throw;
                VerifyExisting(fullDestination, bundle.Manifest);
                // Retain the owned staging directory for inspection on a race.
            }
        }
        catch
        {
            // Retain the owned staging directory for inspection on extraction failure.
            throw;
        }
    }

    private static void ExtractZip(byte[] zipBytes, BundleManifest manifest, string destination)
    {
        Dictionary<string, ManifestFile> expected = new Dictionary<string, ManifestFile>(StringComparer.OrdinalIgnoreCase);
        foreach (ManifestFile file in manifest.files) expected.Add(file.path, file);
        using (MemoryStream source = new MemoryStream(zipBytes))
        using (ZipArchive archive = new ZipArchive(source, ZipArchiveMode.Read, false))
        {
            foreach (ZipArchiveEntry entry in archive.Entries)
            {
                string path = ValidateRelativePath(entry.FullName);
                ManifestFile file = expected[path];
                string target = SafeCombine(destination, path);
                string targetParent = Path.GetDirectoryName(target);
                Directory.CreateDirectory(targetParent);
                using (Stream input = entry.Open())
                using (FileStream output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    input.CopyTo(output);
                }
                VerifyFile(target, file);
            }
        }
    }

    private static string SafeCombine(string root, string relativePath)
    {
        string fullRoot = Path.GetFullPath(root);
        if (!fullRoot.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)) fullRoot += Path.DirectorySeparatorChar;
        string target = Path.GetFullPath(Path.Combine(root, relativePath.Replace('/', '\\')));
        if (!target.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Unsafe payload target path: " + relativePath);
        }
        return target;
    }

    private static void VerifyExisting(string destination, BundleManifest manifest)
    {
        foreach (ManifestFile file in manifest.files)
        {
            string target = SafeCombine(destination, file.path);
            if (!File.Exists(target)) throw new InvalidDataException("Installed payload file is missing: " + file.path);
            VerifyFile(target, file);
        }
    }

    private static void VerifyFile(string path, ManifestFile expected)
    {
        FileInfo info = new FileInfo(path);
        if (info.Length != expected.length)
        {
            throw new InvalidDataException("Installed payload file length mismatch: " + expected.path);
        }
        string actual = HashFile(path);
        if (!String.Equals(actual, expected.sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Installed payload file hash mismatch: " + expected.path);
        }
    }

    private static string HashFile(string path)
    {
        using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            long length;
            return HashStream(stream, out length);
        }
    }

    private static string HashStream(Stream stream, out long length)
    {
        length = 0;
        using (SHA256 sha = SHA256.Create())
        {
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                sha.TransformBlock(buffer, 0, read, buffer, 0);
                length += read;
                if (length > 20L * 1024 * 1024) throw new InvalidDataException("Payload file exceeds the size limit.");
            }
            sha.TransformFinalBlock(new byte[0], 0, 0);
            return ToHex(sha.Hash);
        }
    }

    private static string HashBytes(byte[] value)
    {
        using (SHA256 sha = SHA256.Create()) return ToHex(sha.ComputeHash(value));
    }

    private static string ToHex(byte[] bytes)
    {
        StringBuilder builder = new StringBuilder(bytes.Length * 2);
        foreach (byte value in bytes) builder.Append(value.ToString("x2"));
        return builder.ToString();
    }

    private static Dictionary<string, object> CreateReceipt(string command, Bundle bundle)
    {
        Dictionary<string, object> receipt = new Dictionary<string, object>();
        receipt["schema"] = 1;
        receipt["command"] = command;
        receipt["version"] = bundle.Manifest.version;
        receipt["assemblyVersion"] = bundle.Manifest.assemblyVersion;
        receipt["payloadSha256"] = bundle.PayloadSha256;
        receipt["payloadHashPrefix"] = bundle.PayloadSha256.Substring(0, 12).ToLowerInvariant();
        List<object> files = new List<object>();
        foreach (ManifestFile file in bundle.Manifest.files)
        {
            Dictionary<string, object> item = new Dictionary<string, object>();
            item["path"] = file.path;
            item["length"] = file.length;
            item["sha256"] = file.sha256;
            files.Add(item);
        }
        receipt["files"] = files;
        return receipt;
    }

    private static void WriteFailureReceipt(string path, string command, Exception error)
    {
        if (String.IsNullOrWhiteSpace(path)) return;
        try
        {
            Dictionary<string, object> receipt = new Dictionary<string, object>();
            receipt["schema"] = 1;
            receipt["command"] = command;
            receipt["status"] = "failed";
            receipt["error"] = error.Message;
            WriteReceipt(path, receipt);
        }
        catch { }
    }

    private static void WriteReceipt(string path, Dictionary<string, object> receipt)
    {
        if (String.IsNullOrWhiteSpace(path)) return;
        string fullPath = Path.GetFullPath(path);
        string parent = Path.GetDirectoryName(fullPath);
        if (!String.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
        string temp = fullPath + ".tmp-" + Guid.NewGuid().ToString("N");
        File.WriteAllText(temp, Serializer.Serialize(receipt), new UTF8Encoding(false));
        try
        {
            if (File.Exists(fullPath)) File.Replace(temp, fullPath, null);
            else File.Move(temp, fullPath);
        }
        finally
        {
            if (File.Exists(temp)) try { File.Delete(temp); } catch { }
        }
    }

    private static void ShowError(string message)
    {
        try
        {
            MessageBox.Show(message, "ClaudeGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        catch { }
    }
}