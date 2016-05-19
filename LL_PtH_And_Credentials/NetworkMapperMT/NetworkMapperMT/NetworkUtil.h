#ifndef NETWORKUTIL_H
#define NETWORKUTIL_H

#include <string>

#include <WS2tcpip.h>
#include <Windows.h>


namespace NetworkUtil{
	std::string getCurrentHostname(void);
	BOOL isHostAccessibleTcp(ADDRINFOA *addr);

	BOOL isHostAccessibleTcp(std::string hostnameOrDottedQuad, int port);
	BOOL resolve(std::string hostnameOrDottedQuad, int port, PADDRINFOA *results);

}


#endif