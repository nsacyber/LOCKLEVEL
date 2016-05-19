#include <gmock/gmock.h>

#include <Windows.h>
#include "../NetworkMapperLib/TargetResultsTcp.h"

using namespace testing;

class TargetResultsTcp_F : public Test{
protected:
	TargetResultsTcp result;
	int port;
	BOOL success;
};

TEST_F(TargetResultsTcp_F, GetResultWithNoResultsReturnsFalseOnPortNotInResults){
	port = 80;
	ASSERT_THAT(result.get(port), Eq(FALSE));
}

TEST_F(TargetResultsTcp_F, GetResultWithSomeResultsReturnsFalseOnPortNotInResults){
	port = 80;
	result.add(1, TRUE);
	ASSERT_THAT(result.get(port), Eq(FALSE));
}

TEST_F(TargetResultsTcp_F, AfterAddingAResultWeCanGetItsSuccess){
	port = 80;
	success = TRUE;
	result.add(port, success);


	ASSERT_THAT(result.get(port), Eq(success));
}

TEST_F(TargetResultsTcp_F, TargetIsNotAccessibleBecauseNoPortsAreAccessible){
	ASSERT_THAT(result.isAccessible(), Eq(FALSE));
}

TEST_F(TargetResultsTcp_F, TargetIsAccessibleBecauseFirstPortIsAccessible){
	result.add(80, TRUE);
	ASSERT_THAT(result.isAccessible(), Eq(TRUE));
}

TEST_F(TargetResultsTcp_F, TargetIsAccessibleBecauseSomePortIsAccessible){
	result.add(70, FALSE);
	result.add(80, TRUE);
	ASSERT_THAT(result.isAccessible(), Eq(TRUE));
}

TEST_F(TargetResultsTcp_F, NoOpenPortsAreAvailableOnTargetWithEmptyResults){
	ASSERT_THAT(result.getOpenPorts().size(), Eq(0));
}

TEST_F(TargetResultsTcp_F, OneOpenPortIsAvailableOnTarget){
	result.add(70, FALSE);
	result.add(80, TRUE);
	result.add(65, FALSE);
	ASSERT_THAT(result.getOpenPorts().size(), Eq(1));
}

TEST_F(TargetResultsTcp_F, MultipleOpenPortsAreAvailableOnTarget){
	result.add(70, FALSE);
	result.add(80, TRUE);
	result.add(65, TRUE);
	ASSERT_THAT(result.getOpenPorts().size(), Eq(2));
}

TEST_F(TargetResultsTcp_F, OutputForEmptyPortResults){
	ASSERT_THAT(result.encode(), Eq(std::string(",None")));
}

TEST_F(TargetResultsTcp_F, OutputForOnePortResult){
	result.add(70, FALSE);
	std::string expectedResult = ",70=0";
	ASSERT_THAT(result.encode(), Eq(expectedResult));
}

TEST_F(TargetResultsTcp_F, OutputForTwoPortResults){
	result.add(70, FALSE);
	result.add(80, TRUE);

	//assuming order here.  This isn't necessarily true in an unordered map
	std::string expectedResult = ",70=0,80=1";


	ASSERT_THAT(result.encode(), Eq(expectedResult));
}