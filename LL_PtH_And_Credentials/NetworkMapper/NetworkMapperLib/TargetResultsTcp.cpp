#include "TargetResultsTcp.h"

#include <Windows.h>
#include <string>

void TargetResultsTcp::add(int port, BOOL success){
	results[port] = success;
}

std::string TargetResultsTcp::encode(std::pair<int, BOOL> portSuccessPair) const{
	std::string result = std::to_string(portSuccessPair.first);
	result += "=";
	result += std::to_string(portSuccessPair.second);
	return result;
}

std::string TargetResultsTcp::encode(void) const{
	if (results.size() == 0){
		return ",None";
	}

	std::string output;

	for (auto result : results){
		output += ",";
		std::pair<int, BOOL> resultPair{ result.first, result.second };
		output += encode(resultPair);

	}

	
	return output;
}

BOOL TargetResultsTcp::get(const int port) const{
	if (results.find(port) == results.end()){
		return FALSE;
	}

	return results.at(port);
	
}

std::vector<int> TargetResultsTcp::getOpenPorts() const{
	std::vector<int> openPorts;
	for (auto portItr = results.begin(); portItr != results.end(); portItr++){
		if (isAccessible(portItr->first)){
			openPorts.push_back(portItr->first);
		}
	}
	return openPorts;
}


BOOL TargetResultsTcp::isAccessible(void) const{
	for (auto portItr = results.begin(); portItr != results.end(); portItr++){
		if (get(portItr->first)){
			return TRUE;
		}
	}
	return FALSE;
}

BOOL TargetResultsTcp::isAccessible(const int port) const{
	return get(port);
}

std::unordered_map<int, BOOL>::const_iterator TargetResultsTcp::begin(void){
	return results.begin();
}
std::unordered_map<int, BOOL>::const_iterator TargetResultsTcp::end(void){
	return results.end();
}