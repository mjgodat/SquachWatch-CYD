// Bruce shim — core/ram_profile.h
#pragma once
// RAM profiling stubs — not needed in SquatchWatch
#define RAM_PROFILE_BEGIN(x)
#define RAM_PROFILE_END(x)
inline size_t getFreeHeap() { return ESP.getFreeHeap(); }
