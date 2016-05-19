#ifndef CONCURRENTQUEUE_H
#define CONCURRENTQUEUE_H

#include <Windows.h>
#include <mutex>
#include <queue>
#include <condition_variable>

template<typename T>
class ConcurrentQueue{
public:
	BOOL empty(void) const{return theQueue.empty();}
	void push(const T& val){
		theLock.lock();
		theQueue.push(val);
		theLock.unlock();
		theCondition.notify_one();
	}

	int size(void){
		std::lock_guard<std::mutex> lg(theLock);
		return theQueue.size();
	}

	T pop(void){
		std::unique_lock<std::mutex> lg(theLock);
		while (theQueue.empty()){
			theCondition.wait(lg);
		}
		T item = theQueue.front();
		theQueue.pop();
		return item;
	}


private:
	std::queue<T> theQueue;
	std::mutex theLock;
	std::condition_variable theCondition;
};

#endif