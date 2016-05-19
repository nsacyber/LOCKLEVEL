#ifndef TARGETRESULTSTCP_H
#define TARGETRESULTSTCP_H

#include <Windows.h>
#include <unordered_map>
#include <vector>

class TargetResultsTcp{
public:
	void add(int port, BOOL success);

	std::string encode(void) const;

	BOOL get(const int port) const;
	std::vector<int> getOpenPorts(void) const;
	BOOL isAccessible(void) const;
	BOOL isAccessible(const int port) const;

	std::unordered_map<int, BOOL>::const_iterator begin(void);
	std::unordered_map<int, BOOL>::const_iterator end(void);
	

private:
	std::unordered_map<int, BOOL> results;
	std::string encode(std::pair<int, BOOL>) const;
};



#endif