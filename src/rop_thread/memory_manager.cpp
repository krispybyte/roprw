#include <include/rop_thread/memory_manager.hpp>
#include <include/rop_thread/definitions.hpp>

void MemoryManager::AllocateMemory()
{
    KernelSharedMemoryAllocation = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", sizeof(SharedMemoryData), reinterpret_cast<void*>(MAXULONG64));
    PivotDataAllocation = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", sizeof(PivotData), reinterpret_cast<void*>(MAXULONG64));
    UmDestinationStringArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x20, reinterpret_cast<void*>(MAXULONG64));
    UmSourceStringArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x20, reinterpret_cast<void*>(MAXULONG64));
    UmObjectAttributeArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", sizeof(OBJECT_ATTRIBUTES), reinterpret_cast<void*>(MAXULONG64));
    UmOutputHandleArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x8, reinterpret_cast<void*>(MAXULONG64));
    KmDestinationStringArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x20, reinterpret_cast<void*>(MAXULONG64));
    KmSourceStringArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x20, reinterpret_cast<void*>(MAXULONG64));
    KmObjectAttributeArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", sizeof(OBJECT_ATTRIBUTES), reinterpret_cast<void*>(MAXULONG64));
    KmOutputHandleArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x8, reinterpret_cast<void*>(MAXULONG64));
    GameEProcessOutputArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x8, reinterpret_cast<void*>(MAXULONG64));
    CheatEProcessOutputArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x8, reinterpret_cast<void*>(MAXULONG64));
    SystemEProcessOutputArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x8, reinterpret_cast<void*>(MAXULONG64));
    MainStackAllocation = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", STACK_ALLOC_SIZE, reinterpret_cast<void*>(MAXULONG64));
    InitStackAllocation = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", STACK_ALLOC_SIZE, reinterpret_cast<void*>(MAXULONG64));
    DummyMemoryAllocation = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x8, reinterpret_cast<void*>(MAXULONG64));
    CurrentStackOffsetAddress = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x8, reinterpret_cast<void*>(MAXULONG64));
    StackLimitStoreAddress = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x8, reinterpret_cast<void*>(MAXULONG64));
}

void MemoryManager::FreeMemory()
{
    // TODO: Implement this function.
}

void MemoryManager::InitializeMemory(void* InitStackData, const std::size_t InitStackSize, void* MainStackData, const std::size_t MainStackSize)
{
    // Zero out stack allocations
    KernelCaller.Call<void*, void*, std::size_t>("RtlZeroMemory", MainStackAllocation, STACK_ALLOC_SIZE);
    KernelCaller.Call<void*, void*, std::size_t>("RtlZeroMemory", InitStackAllocation, STACK_ALLOC_SIZE);

    const wchar_t* UmEventNameString = UM_EVENT_NAME;
    const wchar_t* KmEventNameString = KM_EVENT_NAME;
    OBJECT_ATTRIBUTES UmObjectAttributesData;
    OBJECT_ATTRIBUTES KmObjectAttributesData;
    InitializeObjectAttributes(&UmObjectAttributesData, (UNICODE_STRING*)UmDestinationStringArg, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    InitializeObjectAttributes(&KmObjectAttributesData, (UNICODE_STRING*)KmDestinationStringArg, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    std::uint64_t CurrentStackOffsetStartValue = STACK_START_OFFSET;

    void* RetGadgetAddress = reinterpret_cast<void*>(Globals::KernelBase + 0x20043b);
    void* NewRspAddress = reinterpret_cast<void*>(reinterpret_cast<std::uint64_t>(InitStackAllocation) + STACK_START_OFFSET);

    PivotData BootstrapPivotData = {};
    // Set RSP to the allocation of the first stack we will be execution, the 'initialization' stack.
    BootstrapPivotData.NewRsp = NewRspAddress;
    // RBP can be whatever, it's value doesn't seem to be affecting anything of importance to us.
    BootstrapPivotData.NewRbp = NULL;
    // Address we will be jumping to once the bootstrap gadget is done
    // executing. We will just 'ret;' into the first gadget in our new stack.
    BootstrapPivotData.JumpAddress = RetGadgetAddress;

    KernelCaller.Call<void*, void*, void*, std::size_t>("memcpy", PivotDataAllocation, &BootstrapPivotData, sizeof(PivotData));
    KernelCaller.Call<void*, void*, void*, std::size_t>("memcpy", UmSourceStringArg, (void*)UmEventNameString, (lstrlenW(UmEventNameString) + 1) * sizeof(WCHAR));
    KernelCaller.Call<void*, void*, void*, std::size_t>("memcpy", UmObjectAttributeArg, &UmObjectAttributesData, sizeof(OBJECT_ATTRIBUTES));
    KernelCaller.Call<void*, void*, void*, std::size_t>("memcpy", KmSourceStringArg, (void*)KmEventNameString, (lstrlenW(KmEventNameString) + 1) * sizeof(WCHAR));
    KernelCaller.Call<void*, void*, void*, std::size_t>("memcpy", KmObjectAttributeArg, &KmObjectAttributesData, sizeof(OBJECT_ATTRIBUTES));
    KernelCaller.Call<void*, void*, void*, std::size_t>("memcpy", CurrentStackOffsetAddress, &CurrentStackOffsetStartValue, sizeof(CurrentStackOffsetStartValue));
    KernelCaller.Call<void*, void*, void*, std::size_t>("memcpy", (void*)((std::uintptr_t)MainStackAllocation + STACK_START_OFFSET), MainStackData, MainStackSize);
    KernelCaller.Call<void*, void*, void*, std::size_t>("memcpy", (void*)((std::uintptr_t)InitStackAllocation + STACK_START_OFFSET), InitStackData, InitStackSize);
}
