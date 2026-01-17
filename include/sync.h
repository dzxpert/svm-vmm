#pragma once
#include <ntifs.h>

//
// Simple spinlock for hypervisor critical sections
// Used to protect global state accessed from multiple VCPUs
//

typedef struct _HV_SPINLOCK {
    volatile LONG Lock;
} HV_SPINLOCK;

#define HV_SPINLOCK_INIT { 0 }

//
// Acquire spinlock with busy-wait
//
static __forceinline VOID HvSpinLockAcquire(HV_SPINLOCK* Lock)
{
    while (_InterlockedCompareExchange(&Lock->Lock, 1, 0) != 0)
    {
        _mm_pause();
    }
}

//
// Release spinlock
//
static __forceinline VOID HvSpinLockRelease(HV_SPINLOCK* Lock)
{
    _InterlockedExchange(&Lock->Lock, 0);
}

//
// Try to acquire spinlock without blocking
// Returns TRUE if acquired, FALSE if already held
//
static __forceinline BOOLEAN HvSpinLockTryAcquire(HV_SPINLOCK* Lock)
{
    return _InterlockedCompareExchange(&Lock->Lock, 1, 0) == 0;
}
