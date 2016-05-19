#ifndef NETWORKMAPPER_H
#define NETWORKMAPPER_H

#include <WS2tcpip.h>
#include <Windows.h>
#include <vector>

#include "TargetResults.h"
#include "TargetResultsTcp.h"

namespace NetworkUtil{

	class UnableToDetermineHostnameException : public std::exception{
		virtual const std::string traceback() const throw(){
			return "Error determining hostname of networkmapper";
		}
	};




	class WSAError : public std::runtime_error{
	public:
		explicit WSAError(std::string m) : std::runtime_error(m) {};
	};

	class NetworkMapper{
	public:
		NetworkMapper();

		std::string getHostname(void) const { return hostname; }
		std::vector<TargetResults> getResults(void) const;

		TargetResultsTcp mapTargetTcp(const std::string hostnameOrDottedQuad, const std::vector<int>& ports);
		TargetResults mapNeighbor(const std::string hostnameOrDottedQuad, const std::vector<int>& ports);
		void mapNeighbors(const std::vector<std::string>& hostnameOrDottedQuad, const std::vector<int>& ports, BOOL quiet=TRUE);

		std::string toString() const;

		

		
	private:
		std::vector<TargetResults> targetResults;
		std::string hostname;

	};

	BOOL isHostAccessibleTcp(std::string hostnameOrDottedQuad, int port);
	BOOL isHostAccessibleTcp(std::string hostnameOrDottedQuad, const std::vector<int>& ports);
	BOOL isHostAccessibleTcp(ADDRINFOA *results);

	BOOL isWsaInitialized();
	int WSAInitialize(void);
	int WSAUninitialize(void);
	BOOL resolve(std::string hostnameOrDottedQuad, int port, PADDRINFOA *results);

	std::ostream& operator<<(std::ostream& os, const NetworkMapper& mapper);

}
#endif