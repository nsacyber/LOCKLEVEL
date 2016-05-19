#include "TargetResults.h"


std::string TargetResults::encode(void){
	return std::string("," + hostname + tcpResults.encode());
}

void TargetResults::setTcpResults(TargetResultsTcp results){
	tcpResults = results;
}

TargetResultsTcp TargetResults::getTcpResults(void){
	return tcpResults;
}