#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0x00000000L
#endif

typedef NTSTATUS (NTAPI *NT_WRITE_VIRTUAL_MEMORY)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T NumberOfBytesToWrite,
	PSIZE_T NumberOfBytesWritten);

int wmain(void)
{
	BYTE source[] = { 0xDE, 0xAD, 0xBE, 0xEF };
	BYTE destination[sizeof(source)] = { 0 };
	SIZE_T bytesWritten = 0;

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll)
	{
		fprintf(stderr, "[-] GetModuleHandleW(ntdll) - E%lu\n", GetLastError());
		return EXIT_FAILURE;
	}
	FARPROC export = GetProcAddress(ntdll, "NtAccessCheckAndAuditAlarm");
	if (!export)
	{
		fprintf(stderr, "[-] GetProcAddress(NtAccessCheckAndAuditAlarm) - E%lu\n",
			GetLastError());
		return EXIT_FAILURE;
	}

	printf("[+] Before - destination { %02X, %02X, %02X, %02X }\n",
		destination[0], destination[1], destination[2], destination[3]);

	NT_WRITE_VIRTUAL_MEMORY writeMemory = (NT_WRITE_VIRTUAL_MEMORY)export;
	NTSTATUS status = writeMemory(
		GetCurrentProcess(),
		destination,
		source,
		sizeof(source),
		&bytesWritten);

	printf("[+] Call status - 0x%08lX, bytes written %llu\n",
		status, (unsigned long long)bytesWritten);
	if (status != STATUS_SUCCESS)
	{
		fprintf(stderr, "[-] Export did not perform a memory write (unswapped stub)\n");
		return EXIT_FAILURE;
	}

	printf("[+] After - destination { %02X, %02X, %02X, %02X }\n",
		destination[0], destination[1], destination[2], destination[3]);
	if (bytesWritten != sizeof(source)
		|| memcmp(destination, source, sizeof(source)) != 0)
	{
		fprintf(stderr, "[-] Buffer proof mismatch\n");
		return EXIT_FAILURE;
	}
	printf("[+] Proof - buffer copied through the swapped export\n");
	return EXIT_SUCCESS;
}