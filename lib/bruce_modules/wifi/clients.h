// Stub — clients.h (no SSH/telnet on this build)
#ifndef __CLIENTS_H__
#define __CLIENTS_H__
#include <WiFi.h>

inline void telnet_setup() {}
inline void ssh_setup(String host = "") { (void)host; }
inline char *stringTochar(const String &s) { return (char*)s.c_str(); }

#endif
