#include "NetworkUtil.h"
#include "NetworkMapperMgr.h"
#include <chrono>
#include <thread>

BOOL doWork(
	ConcurrentQueue<std::pair<std::string, int>> *workQueue,
	ConcurrentQueue<Result> *resultsQueue,
	std::pair<std::string, int> sentinel){
	std::string srcHost = NetworkUtil::getCurrentHostname();
	for(;;){
		//get the work item
		std::pair<std::string, int> work = workQueue->pop();

		//stop when we get the sentinel value
		if (work == sentinel){
			break;
		}

		//do the work
		BOOL isAccessible = NetworkUtil::isHostAccessibleTcp(work.first, work.second);


		//push results to the result queue
		resultsQueue->push(Result{ srcHost, work.first, work.second, isAccessible });

	}

	return TRUE;

}

BOOL monitorProgress(ConcurrentQueue<std::pair<std::string, int>>* workQueue, int initialSize){
	auto start = std::chrono::high_resolution_clock::now();
	while (workQueue->size() != 0){
		std::this_thread::sleep_for(std::chrono::seconds(10));
		auto now = std::chrono::high_resolution_clock::now();
		std::chrono::duration<double, std::milli> elapsed = now - start;


		std::cout << "#" << (elapsed.count() / 1000.0) << "(s): " << 100 - (((float)workQueue->size() * 100) / initialSize) << "% complete" << std::endl;
		
	}


	return TRUE;
}

BOOL NetworkMapperMgr::run(int nworkers){
	int initialWorkSize = workQueue.size();

	//add the sentinel values to the workQueue
	addSentinels(nworkers);
	
	std::vector<std::future<BOOL>> workersFinished;
	for (int i = 0; i < nworkers; i++){
		workersFinished.push_back(std::async(std::launch::async, doWork, &workQueue, &resultsQueue, getSentinel()));
	}

	//progress monitor for large networks
	std::future<BOOL> monitor = std::async(std::launch::async, monitorProgress, &workQueue, initialWorkSize);

	//wait for threads to finish
	for (size_t i = 0; i < workersFinished.size(); i++){
		workersFinished.at(i).get();
		
	}


	//wait for progress monitor to finish
	monitor.get();


	//post condition
	if (resultsQueue.size() != initialWorkSize){
		std::cout << "#expected " << initialWorkSize << " results, but actually had " << resultsQueue.size() << std::endl;
		return FALSE;
	}
	

	return TRUE;
}

void NetworkMapperMgr::printResults(void){
	while (!resultsQueue.empty()){
		Result result = resultsQueue.pop();
		std::cout << result.src << "," << result.dst << "," << result.port << "," << result.success << std::endl;
	}
}


void NetworkMapperMgr::addSentinels(int nworkers){
	for (int i = 0; i < nworkers; i++){
		workQueue.push(getSentinel());
	}
}


