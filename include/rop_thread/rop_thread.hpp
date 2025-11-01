#pragma once
#include <include/rop_thread/stack_manager.hpp>
#include <include/rop_thread/memory_manager.hpp>
#include <include/driver/arbitrary_call.hpp>

class RopThreadManager
{
private:
	Driver::ArbitraryCaller& KernelCaller;
	MemoryManager* KernelMemory = nullptr;
	StackManager* MainStack = nullptr;
	StackManager* InitStack = nullptr;
	SharedMemoryData* SharedMemory = nullptr;
	HANDLE KmEvent = INVALID_HANDLE_VALUE;
	HANDLE UmEvent = INVALID_HANDLE_VALUE;
	void BuildInitStack(StackManager* Stack, StackManager* PivotStack, const SharedMemoryData* SharedMem);
	void BuildMainStack(StackManager* Stack, const SharedMemoryData* SharedMem);
	void CreateEventObjects();
	void SendPacket();
public:
	RopThreadManager(Driver::ArbitraryCaller& _KernelCaller) : KernelCaller(_KernelCaller)
	{
		CreateEventObjects();

		KernelMemory = new MemoryManager(KernelCaller);
		MainStack = new StackManager(KernelMemory, (std::uintptr_t)KernelMemory->MainStackAllocation + STACK_START_OFFSET);
		InitStack = new StackManager(KernelMemory, (std::uintptr_t)KernelMemory->InitStackAllocation + STACK_START_OFFSET);
		SharedMemory = new SharedMemoryData();

		BuildInitStack(InitStack, MainStack, SharedMemory);
		BuildMainStack(MainStack, SharedMemory);

		KernelMemory->InitializeMemory(
			InitStack->GetStackBuffer(), InitStack->GetStackSize(),
			MainStack->GetStackBuffer(), MainStack->GetStackSize()
		);
	}

	~RopThreadManager()
	{
		delete KernelMemory;
		delete MainStack;
		delete InitStack;
		delete SharedMemory;
	}

	void SpawnThread();
	void SendTargetProcessPid(const int TargetPid);
	void SendReadRequest(const std::uint64_t SourceAddress, const std::uint64_t DestAddress, const std::size_t Size);
};
