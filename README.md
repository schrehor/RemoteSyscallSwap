# RemoteSyscallSwap

An x64 syscall substitution PoC for Windows written in C.

Launches a child process under the Windows debugger API and changes the syscall number in its `NtAccessCheckAndAuditAlarm` stub to the number used by `NtWriteVirtualMemory`.

The companion `SwapTarget` demonstrates the changed behavior by copying four bytes into its own buffer through that export.

## Build target

Windows x64. Visual Studio with the v145 C/C++ toolset and Windows SDK.

Open `RemoteSyscallSwap.slnx` and build both projects in Debug or Release x64.

## Usage

```powershell
.\x64\Release\RemoteSyscallSwap.exe .\x64\Release\SwapTarget.exe
```

Press Enter when prompted to resume the child, or append `--auto` to skip the pause. A solution build places both executables in the same output directory.

Running `SwapTarget.exe` on its own leaves the syscall unchanged, so its copy attempt is expected to fail.

The experiment depends on the expected NTDLL stub layout and refuses unsupported layouts.
