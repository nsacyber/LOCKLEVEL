#include <gmock/gmock.h>

#include <Windows.h>
#include <vector>
#include "../NetworkMapperLib/TargetResults.h"
#include "../NetworkMapperLib/TargetResultsTcp.h"



using namespace testing;

class TargetResultsEncoding_F : public Test{
	void setUp(){
		hostname = "hostname";
		results = TargetResults{ hostname };
		tcpResults = TargetResultsTcp();
	}
protected:
	std::string hostname; 
	TargetResults results;
	TargetResultsTcp tcpResults;
};


TEST_F(TargetResultsEncoding_F, EncodingOfResultsWithNoPortsChecked){
	std::string expectedEncoding = "," + hostname +",None";
	ASSERT_THAT(results.encode(), Eq(expectedEncoding));
}

TEST_F(TargetResultsEncoding_F, EncodingOfResultsWithOnePortChecked){
	tcpResults.add(70, TRUE);

	results.setTcpResults(tcpResults);


	std::string expectedEncoding = "," + hostname + ",70=1";
	ASSERT_THAT(results.encode(), Eq(expectedEncoding));
}

TEST_F(TargetResultsEncoding_F, EncodingOfResultsWithTwoPortsChecked){
	tcpResults.add(70, TRUE);
	tcpResults.add(80, FALSE);
	results.setTcpResults(tcpResults);

	//assuming order here.  This isn't necessarily true in an unordered map
	std::string expectedEncoding = "," + hostname + ",70=1,80=0";
	ASSERT_THAT(results.encode(), Eq(expectedEncoding));
}
