#include "..\NetworkMapperMT\NetworkMapperMgr.h"
#include "..\NetworkMapperMT\ConcurrentQueue.h"


#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <istream>
#include <algorithm>
#include <ctime>
#include <vector>
#include <unordered_set>



#pragma comment(lib, "NetworkMapperMT.lib")

const std::string usage{ "usage: networkmapper_driver.exe <hostsFile> <port1> ... <portn>" };


int WSAInitialize(void){
	WSAData wsaData;
	return WSAStartup(MAKEWORD(2, 2), &wsaData);
}

int WSAUninitialize(void){
	return WSACleanup();
}



void mapNetwork(std::unordered_set<std::string> hostnameOrDottedQuads, std::unordered_set<int> ports){
	NetworkMapperMgr mgr;
	for (auto hodq : hostnameOrDottedQuads){
		for (auto port : ports){
			mgr.addWork(std::pair<std::string, int>{hodq, port});
		}
	}

	mgr.run(20);
	mgr.printResults();
}

std::unordered_set<std::string> getHostnamesFromFile(std::string filename){
	std::unordered_set<std::string> hostnames;
	//open file
	std::ifstream infilestream{ filename };

	if (infilestream.is_open()){
		while (!infilestream.eof()){
			//read each line
			std::string hostname;
			std::getline(infilestream, hostname);

			//remove any spaces from hostname
			hostname.erase(std::remove_if(hostname.begin(), hostname.end(), isspace), hostname.end());
			if (hostname != ""){
				//skip any lines that were just whitespace
				hostnames.insert(hostname);
			}
		}
	}

	return hostnames;
}

BOOL doesFileExist(std::string filename){
	//verify the file exists
	WIN32_FIND_DATAA findFileData;
	HANDLE handle = FindFirstFileA(filename.c_str(), &findFileData);
	if (INVALID_HANDLE_VALUE != handle){
		FindClose(handle);
		return TRUE;
	}
	return FALSE;
}



int main(int argc, char* argv[]){
	WSAInitialize();

	ConcurrentQueue<int> cq;

	//make sure a file is being sent in
	if (argc < 2){
		std::cout << usage.c_str();
		return EXIT_FAILURE;
	}

	std::string filename{ argv[1] };
	if (!doesFileExist(filename)){
		std::cout << "Couldn't find file " + filename << std::endl;
		return EXIT_FAILURE;
	}

	std::unordered_set<std::string> hostnames = getHostnamesFromFile(filename);

	std::unordered_set<int> ports;

	if (argc == 2){
		ports = { 135, 139, 445 };
	}
	else{
		//user wants to supply a list of ports
		for (int i = 2; i < argc; i++){
			int port = atoi(argv[i]);
			if (errno == ERANGE){

				printf("overflow condition occurred in port %s\n", argv[i]);
				return EXIT_FAILURE;
			}


			ports.insert(port);
		}
	}



	std::clock_t start;
	start = std::clock();
	//time it
	mapNetwork(hostnames, ports);


	std::clock_t end = std::clock();
	std::cout << "#Time elapsed: " << ((end - start) / (double)CLOCKS_PER_SEC);


	WSAUninitialize();

	return EXIT_SUCCESS;
}