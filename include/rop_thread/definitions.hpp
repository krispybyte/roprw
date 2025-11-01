#pragma once
#include <cstdint>
#include <cstddef>

/**
    The offset from the memory allocation where our stack starts at.
    The reason for us writing our stack to this offset is that if we try and set RSP 
    to a memory allocation with not enough free memory behind it, we crash with a
    triple fault error.
*/
#define STACK_START_OFFSET  0x2000
/**
    In Windows, the default stack size for a system thread is 0x6000, we should be immitating this.
*/
#define STACK_ALLOC_SIZE    0x6000
/**
    Since our allocation size is 0x6000, which is the default stack size for system threads in
    the Windows operating system, our maximum stack size will be (STACK_ALLOC_SIZE - STACK_START_OFFSET) / 2
    which leaves us with 0x2000.
    The reason it is divided by two is because our current method of looping copies the stack to the next "half"
    of our allocation space, this is because we haven't implemented branch control in ROP.
*/
#define MAXIMUM_STACK_SIZE  ((STACK_ALLOC_SIZE - STACK_START_OFFSET) / 2)
/**
    These are the names for the events we will be creating in order to synchronize our usermode
    program and the kernelmode thread. Keep in mind that the usermode program requires using the
    short name, whereas the kernel handle creator requires a full object name to be specified.
*/
#define UM_EVENT_NAME       L"\\BaseNamedObjects\\Global\\MYSIGNALEVENT_UM"
#define KM_EVENT_NAME       L"\\BaseNamedObjects\\Global\\MYSIGNALEVENT_KM"
#define UM_SHORT_EVENT_NAME L"Global\\MYSIGNALEVENT_UM"
#define KM_SHORT_EVENT_NAME L"Global\\MYSIGNALEVENT_KM"

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
struct PivotData
{
    uint8_t Padding1[0x10];
    void* NewRsp;           // Offset 0x10: New stack pointer
    void* NewRbp;           // Offset 0x18: New base pointer
    uint8_t Padding2[0x30];
    void* JumpAddress;      // Offset 0x50: Jump target (rdx)
};
#if defined(__GNUC__) || defined(__clang__)
__attribute__((packed))
#endif
;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

static_assert(offsetof(PivotData, NewRsp) == 0x10, "NewRsp offset must be 0x10");
static_assert(offsetof(PivotData, NewRbp) == 0x18, "NewRbp offset must be 0x18");
static_assert(offsetof(PivotData, JumpAddress) == 0x50, "JumpAddress offset must be 0x50");
static_assert(sizeof(PivotData) == 0x58, "PivotData size must be 0x58");

struct SharedMemoryData
{
    std::uint64_t WriteSrcEProcess;
    std::uint64_t WriteDstEProcess;
    std::uint64_t WriteSrcAddress;
    std::uint64_t WriteDstAddress;
    std::size_t WriteSize;
    std::uint64_t TargetPid;
    std::uint64_t CheatEProcess;
    std::uint64_t GameEProcess;
    std::uint64_t SystemEProcess;
};
