#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#define EVENT_TIMEOUT_MS 10000
#define RUN_DEADLINE_MS 30000

typedef WORD UMASK;
#define UMASK_WC ((UMASK)0xFFFF)

typedef struct
{
	PROCESS_INFORMATION process;
	BOOL attached;
	BOOL ntdllSeen;
	BOOL kernelbaseSeen;
	BOOL autoMode;
	ULONG_PTR localNtdllBase;
	ULONG_PTR localKernelbaseBase;
	ULONG_PTR loopRva;
	ULONG_PTR childNtdllBase;
	ULONG_PTR childKernelbaseBase;
	ULONG_PTR localStub;
	DWORD sourceNumber;
	DWORD targetNumber;
	ULONGLONG startTick;
	DWORD childExitCode;
	BOOL controlDone;
	BOOL hijacked;
	DWORD64 savedRip;
	ULONG_PTR remoteStub;
	ULONG_PTR protectPage;
	DWORD oldProtection;
	BOOL protectionChanged;
	BOOL patched;
	BYTE originalStubBytes[5];
} SWAP_STATE;

static LPCBYTE SearchForMaskedSignature(
	LPCVOID searchBase,
	SIZE_T searchSize,
	const UMASK* signature,
	SIZE_T signatureCount)
{
	if (!searchBase || !signature || !signatureCount || signatureCount > searchSize)
		return NULL;

	LPCBYTE bytes = (LPCBYTE)searchBase;
	SIZE_T anchor = 0;
	while (anchor < signatureCount && signature[anchor] == UMASK_WC)
		++anchor;
	if (anchor == signatureCount)
		return bytes;

	SIZE_T startCount = searchSize - signatureCount + 1;
	for (SIZE_T i = 0; i < startCount; ++i)
	{
		LPCBYTE window = bytes + i;
		if (window[anchor] != (BYTE)signature[anchor])
			continue;
		BOOL match = TRUE;
		for (SIZE_T j = 0; j < signatureCount; ++j)
		{
			if (signature[j] != UMASK_WC && window[j] != (BYTE)signature[j])
			{
				match = FALSE;
				break;
			}
		}
		if (match)
			return window;
	}
	return NULL;
}

static BOOL FindLoopRva(HMODULE module, ULONG_PTR* rva)
{
	LPCBYTE base = (LPCBYTE)module;
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
		return FALSE;
	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
	{
		if (strcmp((const char*)section->Name, ".text") != 0)
			continue;
		const UMASK loopSignature[] = { 0xEB, 0xFE };
		LPCBYTE hit = SearchForMaskedSignature(
			base + section->VirtualAddress,
			section->Misc.VirtualSize,
			loopSignature,
			2);
		if (hit)
		{
			*rva = (ULONG_PTR)(hit - base);
			return TRUE;
		}
	}
	return FALSE;
}

static BOOL ReadStubNumber(HMODULE ntdll, const char* name, DWORD* number)
{
	FARPROC proc = GetProcAddress(ntdll, name);
	if (!proc)
	{
		fprintf(stderr, "[-] GetProcAddress(%s) - E%lu\n", name, GetLastError());
		return FALSE;
	}
	const BYTE* stub = (const BYTE*)proc;
	if (stub[0] != 0x4C || stub[1] != 0x8B || stub[2] != 0xD1 || stub[3] != 0xB8
		|| stub[5] || stub[6] || stub[7])
	{
		fprintf(stderr, "[-] Unsupported stub layout for %s: %02X %02X %02X %02X\n",
			name, stub[0], stub[1], stub[2], stub[3]);
		return FALSE;
	}
	*number = *(const DWORD*)(stub + 4);
	return TRUE;
}

static BOOL Preflight(SWAP_STATE* state)
{
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	HMODULE kernelbase = GetModuleHandleW(L"kernelbase.dll");
	if (!ntdll || !kernelbase)
	{
		fprintf(stderr, "[-] Required local modules are not loaded\n");
		return FALSE;
	}
	state->localNtdllBase = (ULONG_PTR)ntdll;
	state->localKernelbaseBase = (ULONG_PTR)kernelbase;

	if (!ReadStubNumber(ntdll, "NtAccessCheckAndAuditAlarm", &state->sourceNumber)
		|| !ReadStubNumber(ntdll, "NtWriteVirtualMemory", &state->targetNumber))
		return FALSE;
	state->localStub = (ULONG_PTR)GetProcAddress(ntdll, "NtAccessCheckAndAuditAlarm");

	if (!FindLoopRva(kernelbase, &state->loopRva))
	{
		fprintf(stderr, "[-] No self-loop (EB FE) found in local kernelbase .text\n");
		return FALSE;
	}

	printf("[+] Preflight - source syscall 0x%lX, target syscall 0x%lX\n",
		state->sourceNumber, state->targetNumber);
	printf("[+] Preflight - kernelbase self-loop RVA 0x%llX\n",
		(unsigned long long)state->loopRva);
	return TRUE;
}

static const char* EventName(DWORD code)
{
	switch (code)
	{
		case EXCEPTION_DEBUG_EVENT: return "EXCEPTION";
		case CREATE_THREAD_DEBUG_EVENT: return "CREATE_THREAD";
		case CREATE_PROCESS_DEBUG_EVENT: return "CREATE_PROCESS";
		case EXIT_THREAD_DEBUG_EVENT: return "EXIT_THREAD";
		case EXIT_PROCESS_DEBUG_EVENT: return "EXIT_PROCESS";
		case LOAD_DLL_DEBUG_EVENT: return "LOAD_DLL";
		case UNLOAD_DLL_DEBUG_EVENT: return "UNLOAD_DLL";
		case OUTPUT_DEBUG_STRING_EVENT: return "OUTPUT_DEBUG_STRING";
		case RIP_EVENT: return "RIP";
		default: return "UNKNOWN";
	}
}

static void HandleLoadDll(SWAP_STATE* state, const DEBUG_EVENT* event)
{
	wchar_t path[512] = { 0 };
	DWORD length = GetFinalPathNameByHandleW(
		event->u.LoadDll.hFile,
		path,
		(DWORD)(sizeof(path) / sizeof(path[0])),
		FILE_NAME_NORMALIZED);
	BOOL named = length > 0 && length < sizeof(path) / sizeof(path[0]);
	if (named)
		printf("[+] LOAD_DLL pid=%lu base=0x%llX %ls\n",
			event->dwProcessId,
			(unsigned long long)(ULONG_PTR)event->u.LoadDll.lpBaseOfDll,
			path);
	else
		printf("[+] LOAD_DLL pid=%lu base=0x%llX (name unavailable)\n",
			event->dwProcessId,
			(unsigned long long)(ULONG_PTR)event->u.LoadDll.lpBaseOfDll);

	if (event->u.LoadDll.hFile)
		CloseHandle(event->u.LoadDll.hFile);

	if (named)
	{
		const wchar_t* name = wcsrchr(path, L'\\');
		name = name ? name + 1 : path;
		if (_wcsicmp(name, L"ntdll.dll") == 0)
		{
			state->ntdllSeen = TRUE;
			state->childNtdllBase = (ULONG_PTR)event->u.LoadDll.lpBaseOfDll;
		}
		if (_wcsicmp(name, L"kernelbase.dll") == 0)
		{
			state->kernelbaseSeen = TRUE;
			state->childKernelbaseBase = (ULONG_PTR)event->u.LoadDll.lpBaseOfDll;
		}
	}
}

static BOOL PatchRemoteStub(SWAP_STATE* state)
{
	state->remoteStub = state->childNtdllBase
		+ (state->localStub - state->localNtdllBase);

	BYTE before[8];
	SIZE_T bytesRead = 0;
	if (!ReadProcessMemory(state->process.hProcess, (LPCVOID)state->remoteStub,
		before, sizeof(before), &bytesRead) || bytesRead != sizeof(before))
	{
		fprintf(stderr, "[-] ReadProcessMemory(stub) - E%lu\n", GetLastError());
		return FALSE;
	}
	if (before[0] != 0x4C || before[1] != 0x8B || before[2] != 0xD1
		|| before[3] != 0xB8 || *(DWORD*)(before + 4) != state->sourceNumber)
	{
		fprintf(stderr, "[-] Remote stub layout/number mismatch - unsupported host\n");
		return FALSE;
	}
	printf("[+] Remote stub 0x%llX verified - syscall 0x%lX\n",
		(unsigned long long)state->remoteStub, state->sourceNumber);

	state->protectPage = state->remoteStub & ~(ULONG_PTR)0xFFF;
	if (!VirtualProtectEx(state->process.hProcess, (LPVOID)state->protectPage,
		0x1000, PAGE_EXECUTE_READWRITE, &state->oldProtection))
	{
		fprintf(stderr, "[-] VirtualProtectEx - E%lu\n", GetLastError());
		return FALSE;
	}
	state->protectionChanged = TRUE;
	memcpy(state->originalStubBytes, before + 3, sizeof(state->originalStubBytes));

	BYTE replacement[5] = { 0xB8, 0, 0, 0, 0 };
	*(DWORD*)(replacement + 1) = state->targetNumber;
	SIZE_T bytesWritten = 0;
	if (!WriteProcessMemory(state->process.hProcess, (LPVOID)(state->remoteStub + 3),
		replacement, sizeof(replacement), &bytesWritten)
		|| bytesWritten != sizeof(replacement))
	{
		fprintf(stderr, "[-] WriteProcessMemory(stub) - E%lu\n", GetLastError());
		return FALSE;
	}
	state->patched = TRUE;

	BYTE after[8];
	if (!ReadProcessMemory(state->process.hProcess, (LPCVOID)state->remoteStub,
		after, sizeof(after), &bytesRead) || bytesRead != sizeof(after)
		|| *(DWORD*)(after + 4) != state->targetNumber)
	{
		fprintf(stderr, "[-] Post-write verification failed\n");
		return FALSE;
	}
	printf("[+] Syscall number swapped 0x%lX -> 0x%lX and read back\n",
		state->sourceNumber, state->targetNumber);

	DWORD unused;
	if (!VirtualProtectEx(state->process.hProcess, (LPVOID)state->protectPage,
		0x1000, state->oldProtection, &unused))
	{
		fprintf(stderr, "[-] VirtualProtectEx(restore) - E%lu\n", GetLastError());
		return FALSE;
	}
	state->protectionChanged = FALSE;
	printf("[+] Page protection restored to 0x%lX\n", state->oldProtection);
	return TRUE;
}

static BOOL ControlStage(SWAP_STATE* state, const DEBUG_EVENT* event)
{
	ULONG_PTR remoteLoop = state->childKernelbaseBase + state->loopRva;
	CONTEXT ctx = { .ContextFlags = CONTEXT_CONTROL };

	if (!GetThreadContext(state->process.hThread, &ctx))
	{
		fprintf(stderr, "[-] GetThreadContext - E%lu\n", GetLastError());
		return FALSE;
	}
	state->savedRip = ctx.Rip;
	ctx.Rip = remoteLoop;
	if (!SetThreadContext(state->process.hThread, &ctx))
	{
		fprintf(stderr, "[-] SetThreadContext(loop) - E%lu\n", GetLastError());
		return FALSE;
	}
	state->hijacked = TRUE;
	if (!ContinueDebugEvent(event->dwProcessId, event->dwThreadId, DBG_CONTINUE))
	{
		fprintf(stderr, "[-] ContinueDebugEvent(hijack) - E%lu\n", GetLastError());
		return FALSE;
	}
	printf("[+] Thread redirected - saved RIP 0x%llX, self-loop 0x%llX\n",
		(unsigned long long)state->savedRip, (unsigned long long)remoteLoop);

	Sleep(200);
	if (SuspendThread(state->process.hThread) == (DWORD)-1)
	{
		fprintf(stderr, "[-] SuspendThread - E%lu\n", GetLastError());
		return FALSE;
	}
	CONTEXT spin = { .ContextFlags = CONTEXT_CONTROL };
	if (!GetThreadContext(state->process.hThread, &spin))
	{
		fprintf(stderr, "[-] GetThreadContext(spin) - E%lu\n", GetLastError());
		return FALSE;
	}
	printf("[+] Observed spin RIP 0x%llX (%s)\n",
		(unsigned long long)spin.Rip,
		spin.Rip == remoteLoop ? "matches self-loop" : "UNEXPECTED");
	BOOL spinMatched = spin.Rip == remoteLoop;

	if (!PatchRemoteStub(state))
	{
		spin.Rip = state->savedRip;
		if (!SetThreadContext(state->process.hThread, &spin))
			fprintf(stderr, "[-] SetThreadContext(abort restore) - E%lu\n", GetLastError());
		state->hijacked = FALSE;
		return FALSE;
	}

	spin.Rip = state->savedRip;
	if (!SetThreadContext(state->process.hThread, &spin))
	{
		fprintf(stderr, "[-] SetThreadContext(restore) - E%lu\n", GetLastError());
		return FALSE;
	}
	state->hijacked = FALSE;
	if (!state->autoMode)
	{
		printf("[+] Syscall replaced - press Enter to resume the debuggee\n");
		(void)getchar();
	}
	if (ResumeThread(state->process.hThread) == (DWORD)-1)
	{
		fprintf(stderr, "[-] ResumeThread - E%lu\n", GetLastError());
		return FALSE;
	}
	printf("[+] Original RIP restored and thread resumed\n");
	state->controlDone = TRUE;
	return spinMatched;
}

static void Cleanup(SWAP_STATE* state, BOOL terminateChild)
{
	if (terminateChild)
	{
		if (state->patched && state->process.hProcess)
		{
			SIZE_T written;
			if (WriteProcessMemory(state->process.hProcess,
				(LPVOID)(state->remoteStub + 3),
				state->originalStubBytes, sizeof(state->originalStubBytes), &written))
				printf("[+] Original stub bytes restored on abort\n");
		}
		if (state->protectionChanged && state->process.hProcess)
		{
			DWORD unused;
			if (VirtualProtectEx(state->process.hProcess, (LPVOID)state->protectPage,
				0x1000, state->oldProtection, &unused))
				printf("[+] Page protection restored on abort\n");
		}
		if (state->hijacked && state->process.hThread)
		{
			SuspendThread(state->process.hThread);
			CONTEXT ctx = { .ContextFlags = CONTEXT_CONTROL };
			if (GetThreadContext(state->process.hThread, &ctx))
			{
				ctx.Rip = state->savedRip;
				SetThreadContext(state->process.hThread, &ctx);
			}
			ResumeThread(state->process.hThread);
		}
	}
	if (terminateChild && state->process.hProcess)
	{
		TerminateProcess(state->process.hProcess, 1);
		WaitForSingleObject(state->process.hProcess, 5000);
	}
	if (state->attached)
		DebugActiveProcessStop(state->process.dwProcessId);
	if (state->process.hThread)
		CloseHandle(state->process.hThread);
	if (state->process.hProcess)
		CloseHandle(state->process.hProcess);
}

int wmain(int argc, wchar_t* argv[])
{
	SWAP_STATE state = { 0 };
	const wchar_t* targetPath = NULL;

	for (int i = 1; i < argc; ++i)
	{
		if (wcscmp(argv[i], L"--auto") == 0 && !state.autoMode)
			state.autoMode = TRUE;
		else if (!targetPath && argv[i][0] != L'-')
			targetPath = argv[i];
		else
		{
			fprintf(stderr, "Usage: RemoteSyscallSwap.exe <exePath> [--auto]\n");
			return EXIT_FAILURE;
		}
	}
	if (!targetPath)
	{
		fprintf(stderr, "Usage: RemoteSyscallSwap.exe <exePath> [--auto]\n");
		return EXIT_FAILURE;
	}

	if (!Preflight(&state))
		return EXIT_FAILURE;

	STARTUPINFOW startup = { .cb = sizeof(startup) };
	if (!CreateProcessW(
		targetPath,
		NULL,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
		NULL,
		NULL,
		&startup,
		&state.process))
	{
		fprintf(stderr, "[-] CreateProcessW - E%lu\n", GetLastError());
		return EXIT_FAILURE;
	}
	state.attached = TRUE;
	state.startTick = GetTickCount64();
	DebugSetProcessKillOnExit(FALSE);
	printf("[+] Debuggee pid=%lu launched\n", state.process.dwProcessId);

	DEBUG_EVENT event;
	BOOL running = TRUE;
	while (running)
	{
		if (GetTickCount64() - state.startTick > RUN_DEADLINE_MS)
		{
			fprintf(stderr, "[-] Deadline exceeded waiting for debuggee exit\n");
			Cleanup(&state, TRUE);
			return EXIT_FAILURE;
		}
		if (!WaitForDebugEvent(&event, EVENT_TIMEOUT_MS))
		{
			if (GetLastError() == WAIT_TIMEOUT)
				continue;
			fprintf(stderr, "[-] WaitForDebugEvent - E%lu\n", GetLastError());
			Cleanup(&state, TRUE);
			return EXIT_FAILURE;
		}

		DWORD continueStatus = DBG_CONTINUE;
		switch (event.dwDebugEventCode)
		{
			case CREATE_PROCESS_DEBUG_EVENT:
				printf("[+] CREATE_PROCESS pid=%lu\n", event.dwProcessId);
				if (event.u.CreateProcessInfo.hFile)
					CloseHandle(event.u.CreateProcessInfo.hFile);
				if (event.u.CreateProcessInfo.hThread)
					CloseHandle(event.u.CreateProcessInfo.hThread);
				if (event.u.CreateProcessInfo.hProcess)
					CloseHandle(event.u.CreateProcessInfo.hProcess);
				break;
			case CREATE_THREAD_DEBUG_EVENT:
				printf("[+] CREATE_THREAD pid=%lu tid=%lu\n",
					event.dwProcessId, event.dwThreadId);
				if (event.u.CreateThread.hThread)
					CloseHandle(event.u.CreateThread.hThread);
				break;
			case LOAD_DLL_DEBUG_EVENT:
				HandleLoadDll(&state, &event);
				if (state.ntdllSeen && state.kernelbaseSeen && !state.controlDone)
				{
					if (!ControlStage(&state, &event))
					{
						fprintf(stderr, "[-] Thread-control stage failed\n");
						Cleanup(&state, TRUE);
						return EXIT_FAILURE;
					}
					continue;
				}
				break;
			case EXIT_PROCESS_DEBUG_EVENT:
				state.childExitCode = event.u.ExitProcess.dwExitCode;
				printf("[+] EXIT_PROCESS pid=%lu code=%lu\n",
					event.dwProcessId, state.childExitCode);
				running = FALSE;
				break;
			case EXCEPTION_DEBUG_EVENT:
				printf("[+] EXCEPTION pid=%lu code=0x%08lX first-chance=%d\n",
					event.dwProcessId,
					event.u.Exception.ExceptionRecord.ExceptionCode,
					event.u.Exception.dwFirstChance);
				if (event.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT)
					continueStatus = DBG_EXCEPTION_NOT_HANDLED;
				break;
			default:
				printf("[+] %s pid=%lu tid=%lu\n",
					EventName(event.dwDebugEventCode),
					event.dwProcessId,
					event.dwThreadId);
				break;
		}

		if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continueStatus))
		{
			fprintf(stderr, "[-] ContinueDebugEvent - E%lu\n", GetLastError());
			Cleanup(&state, TRUE);
			return EXIT_FAILURE;
		}
	}

	Cleanup(&state, FALSE);
	printf("[+] Debuggee lifecycle complete - child exit code %lu\n", state.childExitCode);
	return EXIT_SUCCESS;
}