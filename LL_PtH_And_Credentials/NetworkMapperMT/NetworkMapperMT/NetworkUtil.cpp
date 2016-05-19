#include "NetworkUtil.h"

static const enum { PORT_BUF_SIZE = 65 };

std::string NetworkUtil::getCurrentHostname(void){
	char szHostname[256];
	if (SOCKET_ERROR == gethostname(szHostname, sizeof(szHostname))){
		return std::string{};
	}
	else{
		DWORD size = sizeof(szHostname);
		if (!GetComputerNameExA(ComputerNameDnsFullyQualified, szHostname, &size)){
			return "";
		}

		return std::string(szHostname);
	}
}

BOOL NetworkUtil::isHostAccessibleTcp(ADDRINFOA *addr){
	BOOL retStatus = TRUE;
	int iResult;

	//create socket
	SOCKET connectSocket = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
	if (INVALID_SOCKET == connectSocket){
		return FALSE;
	}

	//set timeout for connect in ms
	int recvTimeout = 2000;
	if (SOCKET_ERROR == setsockopt(connectSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)(&recvTimeout), sizeof(int))){
		retStatus = FALSE;
		goto CLOSE_SOCKET_AND_EXIT;
	}

	iResult = connect(connectSocket, addr->ai_addr, (int)addr->ai_addrlen);
	if (SOCKET_ERROR == iResult){
		retStatus = FALSE;
		goto CLOSE_SOCKET_AND_EXIT;

	}

	iResult = shutdown(connectSocket, SD_BOTH);
	if (SOCKET_ERROR == iResult){
		//we were able to connect, but shutdown failed...still return host is accessible
		printf("Error shutting down socket: %d\n", iResult);
	}


CLOSE_SOCKET_AND_EXIT:
	closesocket(connectSocket);


	return retStatus;
}

BOOL NetworkUtil::resolve(std::string hostnameOrDottedQuad, int port, PADDRINFOA *results){
	char portBuffer[PORT_BUF_SIZE] = { 0 };

	//convert port to char*
	if (_itoa_s(port, portBuffer, PORT_BUF_SIZE, 10)){
		//printf("Error converting port to char*\n");
		return FALSE;
	}


	int iResult = getaddrinfo(hostnameOrDottedQuad.c_str(), portBuffer, NULL, results);
	if (iResult != 0){
		//printf("getaddrinfo failed with error: %d\n", WSAGetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL NetworkUtil::isHostAccessibleTcp(std::string hostnameOrDottedQuad, int port){
	ADDRINFOA* results = {0};
	if (resolve(hostnameOrDottedQuad, port, &results)){
		for (ADDRINFOA *resultsItr = results; resultsItr != NULL; resultsItr = resultsItr->ai_next){
			if (isHostAccessibleTcp(resultsItr)){
				return TRUE;
			}
		}
		freeaddrinfo(results);

	}

	return FALSE;
}
