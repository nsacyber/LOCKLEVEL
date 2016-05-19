#include <stdio.h>
#include <vector>
#include <algorithm>
#include <string>
#include <sstream>
#include <iostream>


#include "NetworkUtil.h"

#pragma comment(lib, "ws2_32.lib")


static const enum {PORT_BUF_SIZE = 65};

using namespace NetworkUtil;

NetworkMapper::NetworkMapper(void){
	char szHostname[256];
	if (SOCKET_ERROR == gethostname(szHostname, sizeof(szHostname))){
		hostname = std::string{};
	}
	else{
		DWORD size = sizeof(szHostname);
		if (!GetComputerNameExA(ComputerNameDnsFullyQualified, szHostname, &size)){
			throw NetworkUtil::UnableToDetermineHostnameException();
		}
		
		hostname = std::string(szHostname);
	}
	

}

std::vector<TargetResults> NetworkMapper::getResults(void) const{
	return targetResults;
}


TargetResults NetworkMapper::mapNeighbor(std::string hostnameOrDottedQuad, const std::vector<int>& ports){
	TargetResults targetResults{ hostnameOrDottedQuad };
	targetResults.setTcpResults(mapTargetTcp(hostnameOrDottedQuad, ports));
	return targetResults;
}

void NetworkMapper::mapNeighbors(const std::vector<std::string>& hostnamesOrDottedQuads, const std::vector<int>& ports, BOOL quiet){
	for (auto hostnameOrDottedQuad : hostnamesOrDottedQuads){
		if (!quiet){
			std::cout << "#Mapping host: " << hostnameOrDottedQuad << std::endl;
		}
		try{
			targetResults.push_back(mapNeighbor(hostnameOrDottedQuad, ports));
		}
		catch (...){
			//we want some of the hosts to be mapped even if an exception is thrown on one of them.
		}
	}
}


TargetResultsTcp NetworkMapper::mapTargetTcp(std::string hostnameOrDottedQuad, const std::vector<int>& ports){
	TargetResultsTcp tcpResults;
	for (auto port : ports){
		tcpResults.add(port, isHostAccessibleTcp(hostnameOrDottedQuad, port));
	}


	return tcpResults;
}

std::string NetworkMapper::toString(void) const{
	std::vector<std::string> result;
	if (targetResults.size() == 0){
		return std::string("");
	}

	//get results from TargetResults and populate result with a string
	//representing the output format for each individual tcpresult
	std::string targetHostname;
	std::string port;
	std::string success;
	for (auto targetResult : targetResults){
		targetHostname = targetResult.getHostname();
		TargetResultsTcp theTcpResult = targetResult.getTcpResults();
		for (auto tcpResult = theTcpResult.begin();
			tcpResult != theTcpResult.end();
			tcpResult++){

			result.push_back(hostname + "," + targetHostname + "," + std::to_string(tcpResult->first) + "," + std::to_string(tcpResult->second));

		}
		
		
	}

	//sort the vector for testing purposes (for now)
	//ideally we will not do the vector processing in this function XXX
	std::sort(result.begin(), result.end());

	//convert vector to string and remove any spaces
	std::string sresult{};
	std::string currString;
	for (auto sitr : result){
		
		currString = sitr;
		currString.erase(std::remove_if(currString.begin(), currString.end(), isspace), currString.end());

		sresult += currString + "\n";
	}

	return sresult;
}

/*
std::ostream& NetworkMapper::operator<<(std::ostream& os){
	os << toString();
	return os;
}
*/

std::ostream& NetworkUtil::operator<<(std::ostream& os, const NetworkMapper& mapper){
	return os << mapper.toString();
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

BOOL NetworkUtil::isHostAccessibleTcp(std::string hostnameOrDottedQuad, int port){
	ADDRINFOA* results;
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

BOOL NetworkUtil::isHostAccessibleTcp(std::string hostnameOrDottedQuad, const std::vector<int>& ports){
	for (auto portItr : ports){
		if (isHostAccessibleTcp(hostnameOrDottedQuad, portItr)){
			return TRUE;
		}
	}
	return FALSE;
}



BOOL NetworkUtil::isWsaInitialized(){
	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	return !(s == INVALID_SOCKET && WSAGetLastError() == WSANOTINITIALISED);
}


int NetworkUtil::WSAInitialize(void){
	WSAData wsaData;
	return WSAStartup(MAKEWORD(2, 2), &wsaData);
}

int NetworkUtil::WSAUninitialize(void){
	return WSACleanup();
}

