#ifndef NETWORKMAPPERMGR_H
#define NETWORKMAPPERMGR_H

#include <future>
#include <utility>
#include <iostream>
#include <string>



#include "ConcurrentQueue.h"

#pragma comment(lib, "ws2_32.lib")

struct Result{
public:
	Result(
	std::string _src,
	std::string _dst,
	int _port,
	BOOL _success)
		: src{ _src },
		dst{ _dst },
		port{ _port },
		success{ _success }
	{

	}

	std::string src;
	std::string dst;
	int port;
	BOOL success;

};

class NetworkMapperMgr{
public:
	void addWork(std::pair<std::string, int> work){ return workQueue.push(work); }

	int getPendingWorkRequests(void){ return workQueue.size(); }
	int getNumberOfResults(void){ return resultsQueue.size(); }

	
	
	

	BOOL run(int nworkers);
	void printResults(void);

private:
	ConcurrentQueue<std::pair<std::string, int>> workQueue;
	ConcurrentQueue<Result> resultsQueue;

	std::pair<std::string, int> getSentinel(void){ return std::pair<std::string, int>{"**SENTINEL**", -1}; }
	void addSentinels(int nworkers);
	

};




#endif