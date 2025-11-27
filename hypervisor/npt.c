#include "npt.h"

NTSTATUS NptInitialize(NPT_STATE* State)
{
    if (!State)
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(State, sizeof(NPT_STATE));
    return STATUS_SUCCESS;
}

VOID NptDestroy(NPT_STATE* State)
{
    UNREFERENCED_PARAMETER(State);
}
