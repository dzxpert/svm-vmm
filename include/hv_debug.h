#pragma once

//
// Conditional logging macros for hypervisor
// In Release builds, all logging is stripped out for stealth
//

#ifdef HV_DEBUG
#define HV_TRACE(...) DbgPrint(__VA_ARGS__)
#else
#define HV_TRACE(...)
#endif

#ifdef HV_VERBOSE
#define HV_TRACE_VERBOSE(...) DbgPrint(__VA_ARGS__)
#else
#define HV_TRACE_VERBOSE(...)
#endif

// Always-on critical errors (even in release)
#define HV_ERROR(...) DbgPrint(__VA_ARGS__)
