#include <include/driver/kernel_addresses.hpp>

const std::uint32_t Driver::GetKernelFunctionOffset(const std::string_view& Name)
{
    char SysDir[MAX_PATH];
    GetSystemWindowsDirectoryA(SysDir, MAX_PATH);

    std::string NtosDir(SysDir);

    if (NtosDir.empty())
        return NULL;

    const std::string NtoskrnlPath = NtosDir + "\\System32\\ntoskrnl.exe";

    HMODULE ModuleBase = GetModuleHandleA(NtoskrnlPath.c_str());
    if (!ModuleBase)
    {
        ModuleBase = LoadLibraryExA(
            NtoskrnlPath.c_str(),
            NULL,
            DONT_RESOLVE_DLL_REFERENCES
        );
    }

    if (!ModuleBase)
        return NULL;

    const std::uintptr_t ExportAddress = reinterpret_cast<std::uintptr_t>(GetProcAddress(ModuleBase, Name.data()));
    if (!ExportAddress)
        return NULL;
    
    const std::uint32_t ExportOffset = ExportAddress - reinterpret_cast<std::uintptr_t>(ModuleBase);
    return ExportOffset;
}

const std::uintptr_t Driver::GetKernelModuleBase()
{
    constexpr std::uint8_t SystemModuleInformation = 11;

    PVOID Buffer = nullptr;
    DWORD BufferSize = NULL;
    NTSTATUS Status = NULL;

    Status = Driver::NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(
        SystemModuleInformation),
        NULL,
        NULL,
        &BufferSize
    );

    if (!BufferSize)
        return NULL;

    Buffer = VirtualAlloc(NULL, BufferSize, MEM_COMMIT, PAGE_READWRITE);

    if (!Buffer)
        return NULL;

    Status = Driver::NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(
        SystemModuleInformation),
        Buffer,
        BufferSize,
        &BufferSize
    );

    if (!NT_SUCCESS(Status))
    {
        VirtualFree(Buffer, NULL, MEM_RELEASE);
        return NULL;
    }

    const PRTL_PROCESS_MODULES Modules = reinterpret_cast<PRTL_PROCESS_MODULES>(Buffer);

    for (std::size_t i = 0; i < Modules->NumberOfModules; i++)
    {
        const auto Module = Modules->Modules[i];
        const std::string ModuleName = std::string(reinterpret_cast<const char*>(Module.FullPathName));

        if (ModuleName.find("ntoskrnl.exe"))
        {
            VirtualFree(Buffer, NULL, MEM_RELEASE);
            return reinterpret_cast<std::uintptr_t>(Module.ImageBase);
        }
    }

    return NULL;
}