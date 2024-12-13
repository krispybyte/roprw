#include <include/driver/arbitrary_call.hpp>
#include <include/utils/utils.hpp>

int main()
{
    if (!Utils::EnableDebugPrivilege())
    {
        std::exception("Failed to enable debug privileges");
        return EXIT_FAILURE;
    }

    Driver::ArbitraryCaller KernelCaller = Driver::ArbitraryCaller();

    // Causes any calls of NtShutdownSystem to redirect to NtAllocateUuids
    KernelCaller.RedirectCallByName("NtShutdownSystem", "NtAllocateUuids");

    return EXIT_SUCCESS;
}