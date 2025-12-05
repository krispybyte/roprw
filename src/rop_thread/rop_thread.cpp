#include <include/rop_thread/rop_thread.hpp>
#include <include/utils/utils.hpp>

void RopThreadManager::BuildInitStack(StackManager* Stack, StackManager* PivotStack, const SharedMemoryData* SharedMem)
{
    // Open handle to usermode event in the kernel
    Stack->AddFunctionCall("RtlInitUnicodeString", (std::uint64_t)KernelMemory->UmDestinationStringArg, (std::uint64_t)KernelMemory->UmSourceStringArg);
    Stack->AddFunctionCall("ZwOpenEvent", (std::uint64_t)KernelMemory->UmOutputHandleArg, EVENT_MODIFY_STATE | SYNCHRONIZE, (std::uint64_t)KernelMemory->UmObjectAttributeArg);

    Stack->AddFunctionCall("RtlInitUnicodeString", (std::uint64_t)KernelMemory->KmDestinationStringArg, (std::uint64_t)KernelMemory->KmSourceStringArg);
    Stack->AddFunctionCall("ZwOpenEvent", (std::uint64_t)KernelMemory->KmOutputHandleArg, EVENT_MODIFY_STATE | SYNCHRONIZE, (std::uint64_t)KernelMemory->KmObjectAttributeArg);

    // Get usermode process
    Stack->AddFunctionCall("PsLookupProcessByProcessId", GetCurrentProcessId(), (std::uint64_t)KernelMemory->CheatEProcessOutputArg);
    Stack->AddFunctionCall("PsLookupProcessByProcessId", 4, (std::uint64_t)KernelMemory->SystemEProcessOutputArg);

    Stack->AwaitUsermode(KernelMemory->UmOutputHandleArg);
    Stack->CallMmCopyVirtualMemory(KernelMemory->CheatEProcessOutputArg, (void*)SharedMem, KernelMemory->SystemEProcessOutputArg, KernelMemory->KernelSharedMemoryAllocation, 0, sizeof(SharedMemoryData), KernelMemory->DummyMemoryAllocation);
    Stack->ReadIntoRcx(reinterpret_cast<std::uint64_t>(KernelMemory->KernelSharedMemoryAllocation) + offsetof(SharedMemoryData, TargetPid));
    Stack->SetRdx((std::uint64_t)KernelMemory->GameEProcessOutputArg);
    Stack->AddFunctionCall("PsLookupProcessByProcessId");

    // Copy EProcess structures to usermode
    Stack->CallMmCopyVirtualMemory(KernelMemory->SystemEProcessOutputArg, KernelMemory->CheatEProcessOutputArg, KernelMemory->CheatEProcessOutputArg, (void*)((uint64_t)SharedMem + offsetof(SharedMemoryData, CheatEProcess)), 0, sizeof(std::uint64_t), KernelMemory->DummyMemoryAllocation);
    Stack->CallMmCopyVirtualMemory(KernelMemory->SystemEProcessOutputArg, KernelMemory->GameEProcessOutputArg, KernelMemory->CheatEProcessOutputArg, (void*)((uint64_t)SharedMem + offsetof(SharedMemoryData, GameEProcess)), 0, sizeof(std::uint64_t), KernelMemory->DummyMemoryAllocation);
    Stack->CallMmCopyVirtualMemory(KernelMemory->SystemEProcessOutputArg, KernelMemory->SystemEProcessOutputArg, KernelMemory->CheatEProcessOutputArg, (void*)((uint64_t)SharedMem + offsetof(SharedMemoryData, SystemEProcess)), 0, sizeof(std::uint64_t), KernelMemory->DummyMemoryAllocation);

    Stack->SignalUsermode(KernelMemory->KmOutputHandleArg);

    Stack->PivotToNewStack(*PivotStack);
}

void RopThreadManager::BuildMainStack(StackManager* Stack, const SharedMemoryData* SharedMem)
{
    Stack->AwaitUsermode(KernelMemory->UmOutputHandleArg);
    // Copy user shared memory into our buffer
    Stack->CallMmCopyVirtualMemory(KernelMemory->CheatEProcessOutputArg, (void*)SharedMem, KernelMemory->SystemEProcessOutputArg, KernelMemory->KernelSharedMemoryAllocation, 0, sizeof(SharedMemoryData), KernelMemory->DummyMemoryAllocation);

    // Read from game process to cheat process
    // first arg
    Stack->ReadIntoRcx(reinterpret_cast<std::uint64_t>(KernelMemory->KernelSharedMemoryAllocation) + offsetof(SharedMemoryData, WriteSrcEProcess));
    // fourth arg (shared memory + offsetof(dest addr))
    Stack->SetRdx(reinterpret_cast<std::uint64_t>(KernelMemory->KernelSharedMemoryAllocation) + offsetof(SharedMemoryData, WriteDstAddress));
    Stack->AddGadget(0x21307f, "mov rax, rdx; ret;");
    Stack->ReadRaxIntoRax();
    Stack->MovRaxIntoR9();
    // third arg
    Stack->SetRdx(reinterpret_cast<std::uint64_t>(KernelMemory->KernelSharedMemoryAllocation) + offsetof(SharedMemoryData, WriteDstEProcess));
    Stack->AddGadget(0x21307f, "mov rax, rdx; ret;");
    Stack->ReadRaxIntoRax();
    Stack->MovRaxIntoR8();
    // second arg
    Stack->SetRdx(reinterpret_cast<std::uint64_t>(KernelMemory->KernelSharedMemoryAllocation) + offsetof(SharedMemoryData, WriteSrcAddress));
    Stack->AddGadget(0x21307f, "mov rax, rdx; ret;");
    Stack->ReadRaxIntoRax();
    Stack->AddGadget(0x3e8baf, "cmp esi, esi; ret;");
    Stack->AddGadget(0x2cbad3, "mov rdx, rax; jne 0x......; add rsp, 0x28; ret;");
    Stack->AddPadding(0x28);
    // perform call
    Stack->AlignStack();
    Stack->AddGadget(Driver::GetKernelFunctionOffset("MmCopyVirtualMemory"), "MmCopyVirtualMemory address");
    // clean up shadow space + args after call
    Stack->AddGadget(0x20268c, "add rsp, 0x38; ret;");
    // shadow space
    Stack->AddPadding(0x20);
    // stack args
    Stack->AddValue(sizeof(void*), "size");
    Stack->AddValue(0, "previous mode");
    Stack->AddValue(reinterpret_cast<std::uint64_t>(KernelMemory->DummyMemoryAllocation), "bytes addr");

    Stack->SignalUsermode(KernelMemory->KmOutputHandleArg);
    Stack->LoopBack();
}

void RopThreadManager::CreateEventObjects()
{
    // Create kernelmode event
    KmEvent = CreateEventW(NULL, FALSE, FALSE, KM_SHORT_EVENT_NAME);

    // Create usermode event
    UmEvent = CreateEventW(NULL, FALSE, FALSE, UM_SHORT_EVENT_NAME);

    if (UmEvent == INVALID_HANDLE_VALUE || KmEvent == INVALID_HANDLE_VALUE)
    {
        std::exception("Failed to create synchronization event objects");
    }
}

void RopThreadManager::SendPacket()
{
    // Alert the kernel thread by setting the event it awaits on
    SetEvent(UmEvent);

    // Wait for the kernel thread to perform the operation and alert us
    WaitForSingleObject(KmEvent, INFINITE);
}

void RopThreadManager::SpawnThread()
{
    // mov rdx, qword ptr [rcx + 0x50]; mov rbp, qword ptr [rcx + 0x18]; mov rsp, qword ptr [rcx + 0x10]; jmp rdx;
    void* BootstrapGadget = (void*)(Globals::KernelBase + 0x6999c0);

    HANDLE KernelThreadHandle;
    NTSTATUS ThreadCreationStatus = KernelCaller.Call<NTSTATUS, HANDLE*, ULONG, OBJECT_ATTRIBUTES*, HANDLE, void*, void*, void*>(
        "PsCreateSystemThread",
        &KernelThreadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        BootstrapGadget,
        KernelMemory->PivotDataAllocation
    );

    if (!NT_SUCCESS(ThreadCreationStatus))
    {
        std::exception("PsCreateSystemThread failed");
    }

    KernelCaller.Call<void*, HANDLE>("ZwClose", KernelThreadHandle);
}

void RopThreadManager::SendTargetProcessPid(const int TargetPid)
{
    SharedMemory->TargetPid = TargetPid;
    SendPacket();
}

void RopThreadManager::SendReadRequest(const std::uint64_t SourceAddress, const std::uint64_t DestAddress, const std::size_t Size)
{
    SharedMemory->WriteSrcEProcess = SharedMemory->GameEProcess;
    SharedMemory->WriteDstEProcess = SharedMemory->CheatEProcess;
    SharedMemory->WriteSrcAddress = SourceAddress;
    SharedMemory->WriteDstAddress = DestAddress;
    SharedMemory->WriteSize = Size;
    SendPacket();
}

void RopThreadManager::SendWriteRequest(const std::uint64_t SourceAddress, const std::uint64_t DestAddress, const std::size_t Size)
{
    SharedMemory->WriteSrcEProcess = SharedMemory->CheatEProcess;
    SharedMemory->WriteDstEProcess = SharedMemory->GameEProcess;
    SharedMemory->WriteSrcAddress = SourceAddress;
    SharedMemory->WriteDstAddress = DestAddress;
    SharedMemory->WriteSize = Size;
    SendPacket();
}
