#ifndef TARGETRESULT_H
#define TARGETRESULT_H

#include "TargetResultsTcp.h"

class TargetResults{
public:
	TargetResults(){};
	explicit TargetResults(std::string hostname)	
		: hostname(hostname){
	}

	std::string encode(void);
	std::string getHostname(void) const { return hostname; }
	TargetResultsTcp getTcpResults(void);
	void setTcpResults(TargetResultsTcp newResults);


	
private:
	std::string hostname;
	TargetResultsTcp tcpResults;
};

#endif