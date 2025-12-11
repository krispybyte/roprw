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
	void SendReadRequest(const std::uint64_t SourceAddress, const std::uint64_t DestAddress, const std::size_t Size);
	void SendWriteRequest(const std::uint64_t SourceAddress, const std::uint64_t DestAddress, const std::size_t Size);
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

	template<typename T>
	T Read(const std::uint64_t Address)
	{
		static_assert(std::is_trivially_copyable_v<T>, "RopThreadManager::Read<T> only supports trivially copyable types");

		std::byte Buffer[sizeof(T)];
		const T* BufferPtr = reinterpret_cast<T*>(Buffer);

		SendReadRequest(
			Address,
			reinterpret_cast<std::uint64_t>(BufferPtr),
			sizeof(T)
		);

		return *BufferPtr;
	}

	template<typename T>
	void Write(const std::uint64_t Address, const T& Value)
	{
		static_assert(std::is_trivially_copyable_v<T>, "RopThreadManager::Write<T> only supports trivially copyable types");

		SendWriteRequest(
			reinterpret_cast<std::uint64_t>(&Value),
			Address,
			sizeof(T)
		);
	}
};
