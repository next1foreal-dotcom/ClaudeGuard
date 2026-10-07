using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public sealed class ClaudeGuardJob : IDisposable {
    [StructLayout(LayoutKind.Sequential)] struct BASIC_LIMIT { public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass, SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)] struct IO_COUNTERS { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)] struct EXTENDED_LIMIT { public BASIC_LIMIT BasicLimitInformation; public IO_COUNTERS IoInfo; public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed; }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct STARTUPINFO { public int cb; public string lpReserved, lpDesktop, lpTitle; public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }
    [StructLayout(LayoutKind.Sequential)] struct PROCESSINFO { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref EXTENDED_LIMIT info, uint length);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcess(string app, StringBuilder command, IntPtr procAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string directory, ref STARTUPINFO startup, out PROCESSINFO process);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle, uint timeout);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    IntPtr job, process;
    public int ProcessId { get; private set; }
    public bool IsRunning { get { return process != IntPtr.Zero && WaitForSingleObject(process, 0) == 258; } }
    public uint ExitCode { get { uint code; GetExitCodeProcess(process, out code); return code; } }
    public static string Quote(string value) {
        if (value == null) value = "";
        StringBuilder result = new StringBuilder("\""); int slashes = 0;
        foreach (char c in value) {
            if(c == '\\') { slashes++; continue; }
            if(c == '"') { result.Append('\\', slashes * 2 + 1); result.Append(c); slashes = 0; continue; }
            result.Append('\\', slashes); slashes = 0; result.Append(c);
        }
        result.Append('\\', slashes * 2); result.Append('"'); return result.ToString();
    }
    public ClaudeGuardJob(string app, string[] arguments, string directory, bool visible) {
        job = CreateJobObject(IntPtr.Zero, null);
        if(job == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        EXTENDED_LIMIT limits = new EXTENDED_LIMIT(); limits.BasicLimitInformation.LimitFlags = 0x2000;
        if(!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(limits))) { int e=Marshal.GetLastWin32Error(); Dispose(); throw new Win32Exception(e); }
        StringBuilder command = new StringBuilder(Quote(app));
        foreach(string arg in arguments) command.Append(" ").Append(Quote(arg));
        STARTUPINFO startup = new STARTUPINFO(); startup.cb=Marshal.SizeOf(startup);
        PROCESSINFO info;
        uint flags = 0x4u | (visible ? 0x10u : 0x08000000u);
        if(!CreateProcess(app,command,IntPtr.Zero,IntPtr.Zero,false,flags,IntPtr.Zero,directory,ref startup,out info)) { int e=Marshal.GetLastWin32Error(); Dispose(); throw new Win32Exception(e); }
        process=info.hProcess; ProcessId=info.dwProcessId;
        if(!AssignProcessToJobObject(job, process)) { int e=Marshal.GetLastWin32Error(); TerminateProcess(process,125); CloseHandle(info.hThread); Dispose(); throw new Win32Exception(e); }
        if(ResumeThread(info.hThread)==0xffffffff) { int e=Marshal.GetLastWin32Error(); CloseHandle(info.hThread); Dispose(); throw new Win32Exception(e); }
        CloseHandle(info.hThread);
    }
    public void Dispose() { if(job != IntPtr.Zero) { CloseHandle(job); job=IntPtr.Zero; } if(process != IntPtr.Zero) { CloseHandle(process); process=IntPtr.Zero; } }
}