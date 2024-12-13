#pragma once
#include <cstdint>
#include <Windows.h>
#include <exception>

namespace Driver
{
	class Athpexnt
	{
	private:
		class MemoryWriteIoctlPacket
		{
		private:
			std::uint64_t Destination;
			std::uint64_t Source;
			std::uint32_t Size;
		public:
			MemoryWriteIoctlPacket(const std::uint64_t Dest, const std::uint64_t Src, const std::uint32_t Size)
				: Destination(Dest), Source(Src), Size(Size)
			{
			}
		};

		HANDLE DriverHandle = NULL;
        const std::uint32_t WritePrimitiveDispatchCode = 0x81000000;

		Athpexnt()
		{
			this->DriverHandle = CreateFileA("\\\\.\\ATHpEx",
				GENERIC_READ,
				NULL,
				NULL,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				NULL
			);

			if (this->DriverHandle == INVALID_HANDLE_VALUE)
				throw std::exception("Failed opening a handle to the driver");
		}
	public:
		~Athpexnt()
		{
			CloseHandle(this->DriverHandle);
		}

		static Athpexnt* GetInstance();
		bool WritePhysicalMemory(const void* To, const void* From, const std::uint32_t Size) const;

        template<typename T>
        bool WritePhysicalMemory(const void* VirtualDestination, const T VirtualSource) const
        {
            const MemoryWriteIoctlPacket IoctlPacketData(
                reinterpret_cast<std::uint64_t>(VirtualDestination),
                reinterpret_cast<std::uint64_t>(&VirtualSource),
                sizeof(VirtualSource)
            );

            std::uint32_t BytesReturned = 0;
            if (!DeviceIoControl(this->DriverHandle,
                WritePrimitiveDispatchCode,
                reinterpret_cast<const void*>(&IoctlPacketData),
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
	};
}