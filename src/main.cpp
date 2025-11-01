#include <numeric>
#include <iostream>
#include <include/driver/arbitrary_call.hpp>
#include <include/utils/utils.hpp>
#include <include/globals.hpp>
#include <include/rop_thread/rop_thread.hpp>

int main()
{
    if (!Utils::EnableDebugPrivilege())
    {
        std::exception("Failed to enable debug privileges");
        return EXIT_FAILURE;
    }

    const std::uintptr_t RandomValidThreadAddress = Utils::FindRandomValidThreadAddress();
    if (!RandomValidThreadAddress)
    {
        std::exception("Failed to find a random valid thread address");
        return EXIT_FAILURE;
    }

    Globals::WindowsBuild = Utils::GetWindowsDisplayVersion();
    if (Globals::WindowsBuild.empty())
    {
        std::exception("Failed to find the windows build being used");
        return EXIT_FAILURE;
    }

    Globals::KernelBase = Driver::GetKernelModuleBase();
    if (!Globals::KernelBase)
    {
        std::exception("Failed to find ntoskrnl.exe base");
        return EXIT_FAILURE;
    }

    std::printf("[+] Windows build: %s\n", Globals::WindowsBuild.c_str());
    std::printf("[+] New thread address to be used @ 0x%p\n", RandomValidThreadAddress);
    std::printf("[+] ntoskrnl.exe @ 0x%p\n", Globals::KernelBase);

    Driver::ArbitraryCaller KernelCaller = Driver::ArbitraryCaller("NtReadFileScatter");
    RopThreadManager RopThread(KernelCaller);

    std::cin.get();

    RopThread.SpawnThread();

    const int TargetPid = Utils::GetPidByName("notepad.exe");

    RopThread.SendTargetProcessPid(TargetPid);

    const std::uint64_t NotepadBase = Utils::GetModuleBaseAddress(TargetPid, "notepad.exe");

    void* ReadBuffer = malloc(4096);
    RtlZeroMemory(ReadBuffer, 4096);
    RopThread.SendReadRequest(NotepadBase, (std::uint64_t)ReadBuffer, 8);
    printf("read 8 bytes: 0x%p\n", *(void**)ReadBuffer);

    std::cin.get();

    return EXIT_SUCCESS;
}