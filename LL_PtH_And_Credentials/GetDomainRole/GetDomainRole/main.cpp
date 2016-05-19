#include <Windows.h>
#include <iostream>
#include <string>
#include <fstream>

static const std::string UNKNOWN_COMPUTERNAME{ "UNKNOWN_COMPUTERNAME" };
static const std::string ERROR_RESULT_STRING{ "ERROR" };
static const std::string UNKNOWN_RESULT_STRING{ "UNKNOWN" };
static const std::string WORKSTATION_RESULT_STRING{ "WORKSTATION" };
static const std::string DC_RESULT_STRING{ "DC" };
static const std::string SERVER_RESULT_STRING{ "SERVER" };

namespace ComputerUtil{
	BOOL IsProductType(BYTE wProductType){
		DWORDLONG dwlConditionMask = 0;
		OSVERSIONINFOEX osvi = { 0 };
		osvi.dwOSVersionInfoSize = sizeof(osvi);
		osvi.wProductType = wProductType;

		VER_SET_CONDITION(dwlConditionMask, VER_PRODUCT_TYPE, VER_EQUAL);

		return VerifyVersionInfo(&osvi, VER_PRODUCT_TYPE, dwlConditionMask);
	}

	BOOL IsWorkstation(){
		return IsProductType(VER_NT_WORKSTATION);
	}

	BOOL IsDomainController(){
		return IsProductType(VER_NT_DOMAIN_CONTROLLER);
	}

	BOOL IsServer(){
		return IsProductType(VER_NT_SERVER);
	}

	std::string GetFqdn(){
		std::string fqdn{};
		char *buf = NULL;
		DWORD returnedBufSize = 0;
		::GetComputerNameExA(ComputerNameDnsFullyQualified, buf, &returnedBufSize);

		DWORD newSize = returnedBufSize * sizeof(char);
		buf = (char*)malloc(newSize);

		if (GetComputerNameExA(ComputerNameDnsFullyQualified, buf, &newSize)){
			fqdn = buf;
		}

		free(buf);

		return fqdn;
	}

	std::string GetComputerName(){
		char buf[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
		DWORD size = sizeof(buf);
		if (::GetComputerNameA(buf, &size)){
			return std::string{ buf };
		}
		else{
			return std::string{ UNKNOWN_COMPUTERNAME };
		}
		
	}

	std::string GetComputerRole(){
		if (ComputerUtil::IsWorkstation()){
			return std::string{ WORKSTATION_RESULT_STRING };
		}
		else if (ComputerUtil::IsDomainController()){
			return std::string{ DC_RESULT_STRING };
		}

		else if (ComputerUtil::IsServer()){
			return std::string{ SERVER_RESULT_STRING };
		}
		else{
			return std::string{ UNKNOWN_RESULT_STRING };
		}
	}
}

int main(void){

	std::string computername = ComputerUtil::GetFqdn();
	std::string role = ComputerUtil::GetComputerRole();

	std::string result{ computername + "=" + role };

	std::cout << result << std::endl;

	return EXIT_SUCCESS;
}