#pragma once
#include <include/driver/arbitrary_call.hpp>

class MemoryManager
{
private:
	Driver::ArbitraryCaller& KernelCaller;
	void AllocateMemory();
	void FreeMemory();
public:
	void* KernelSharedMemoryAllocation = nullptr;
	void* PivotDataAllocation = nullptr;
	void* UmDestinationStringArg = nullptr;
	void* UmSourceStringArg = nullptr;
	void* UmObjectAttributeArg = nullptr;
	void* UmOutputHandleArg = nullptr;
	void* KmDestinationStringArg = nullptr;
	void* KmSourceStringArg = nullptr;
	void* KmObjectAttributeArg = nullptr;
	void* KmOutputHandleArg = nullptr;
	void* GameEProcessOutputArg = nullptr;
	void* CheatEProcessOutputArg = nullptr;
	void* SystemEProcessOutputArg = nullptr;
	void* MainStackAllocation = nullptr;
	void* InitStackAllocation = nullptr;
	void* DummyMemoryAllocation = nullptr;
	void* CurrentStackOffsetAddress = nullptr;
	void* StackLimitStoreAddress = nullptr;
	
	MemoryManager(Driver::ArbitraryCaller& _KernelCaller) : KernelCaller(_KernelCaller)
	{
		this->AllocateMemory();
	}

	~MemoryManager()
	{
		this->FreeMemory();
	}

	void InitializeMemory(void* InitStackData, const std::size_t InitStackSize, void* MainStackData, const std::size_t MainStackSize);
};
