#include <include/rop_thread/memory_manager.hpp>
#include <include/rop_thread/definitions.hpp>

void MemoryManager::AllocateMemory()
{
    const wchar_t* UmEventNameString = UM_EVENT_NAME;
    const wchar_t* KmEventNameString = KM_EVENT_NAME;
    const int UmEventNameStringLength = (lstrlenW(UmEventNameString) + 1) * sizeof(WCHAR);
    const int KmEventNameStringLength = (lstrlenW(KmEventNameString) + 1) * sizeof(WCHAR);

    KernelSharedMemoryAllocation = KernelCaller.Call<void*, SIZE_T, ULONG>("ExAllocatePool2", (ULONG64)POOL_FLAG_NON_PAGED, sizeof(SharedMemoryData), ALLOC_TAG);
    PivotDataAllocation = KernelCaller.Call<void*, SIZE_T, ULONG>("ExAllocatePool2", (ULONG64)POOL_FLAG_NON_PAGED, sizeof(PivotData), ALLOC_TAG);
    UmDestinationStringArg = KernelCaller.Call<void*, SIZE_T, ULONG>("ExAllocatePool2", (ULONG64)POOL_FLAG_NON_PAGED, 0x8, ALLOC_TAG);
    UmSourceStringArg = KernelCaller.Call<void*, SIZE_T, ULONG>("ExAllocatePool2", (ULONG64)POOL_FLAG_NON_PAGED, UmEventNameStringLength, ALLOC_TAG);
    UmObjectAttributeArg = KernelCaller.Call<void*, SIZE_T, ULONG>("ExAllocatePool2", (ULONG64)POOL_FLAG_NON_PAGED, sizeof(OBJECT_ATTRIBUTES), ALLOC_TAG);
    UmOutputHandleArg = KernelCaller.Call<void*, SIZE_T, ULONG>("ExAllocatePool2", (ULONG64)POOL_FLAG_NON_PAGED, 0x8, ALLOC_TAG);
    KmDestinationStringArg = KernelCaller.Call<void*, SIZE_T, ULONG>("ExAllocatePool2", (ULONG64)POOL_FLAG_NON_PAGED, 0x8, ALLOC_TAG);
    KmSourceStringArg = KernelCaller.Call<void*, SIZE_T, ULONG>("ExAllocatePool2", (ULONG64)POOL_FLAG_NON_PAGED, KmEventNameStringLength, ALLOC_TAG);
    KmObjectAttributeArg = KernelCaller.Call<void*, SIZE_T, ULONG>("ExAllocatePool2", (ULONG64)POOL_FLAG_NON_PAGED, sizeof(OBJECT_ATTRIBUTES), ALLOC_TAG);
    KmOutputHandleArg = KernelCaller.Call<void*, SIZE_T, ULONG>("ExAllocatePool2", (ULONG64)POOL_FLAG_NON_PAGED, 0x8, ALLOC_TAG);
    GameEProcessOutputArg = KernelCaller.Call<void*, SIZE_T, ULONG>("ExAllocatePool2", (ULONG64)POOL_FLAG_NON_PAGED, 0x8, ALLOC_TAG);
    CheatEProcessOutputArg = KernelCaller.Call<void*, SIZE_T, ULONG>("ExAllocatePool2", (ULONG64)POOL_FLAG_NON_PAGED, 0x8, ALLOC_TAG);
    SystemEProcessOutputArg = KernelCaller.Call<void*, SIZE_T, ULONG>("ExAllocatePool2", (ULONG64)POOL_FLAG_NON_PAGED, 0x8, ALLOC_TAG);
    InitStackAllocation = KernelCaller.Call<void*, SIZE_T, ULONG>("ExAllocatePool2", (ULONG64)POOL_FLAG_NON_PAGED, STACK_ALLOC_SIZE, ALLOC_TAG);
    MainStackAllocation = KernelCaller.Call<void*, SIZE_T, ULONG>("ExAllocatePool2", (ULONG64)POOL_FLAG_NON_PAGED, STACK_ALLOC_SIZE, ALLOC_TAG);
    DummyMemoryAllocation = KernelCaller.Call<void*, SIZE_T, ULONG>("ExAllocatePool2", (ULONG64)POOL_FLAG_NON_PAGED, 0x8, ALLOC_TAG);
    CurrentStackOffsetAddress = KernelCaller.Call<void*, SIZE_T, ULONG>("ExAllocatePool2", (ULONG64)POOL_FLAG_NON_PAGED, 0x8, ALLOC_TAG);
    StackLimitStoreAddress = KernelCaller.Call<void*, SIZE_T, ULONG>("ExAllocatePool2", (ULONG64)POOL_FLAG_NON_PAGED, 0x8, ALLOC_TAG);
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
