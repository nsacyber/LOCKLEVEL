#include <gmock/gmock.h>

#include "..\NetworkMapperMT\NetworkMapperMgr.h"


using namespace testing;


class MgrWorkQueue_F : public Test{
protected:
	NetworkMapperMgr mgr;
	std::pair<std::string, int> work{ "host", 2 };
};

TEST_F(MgrWorkQueue_F, WorkQueueIsEmptyInitially){
	
	ASSERT_THAT(mgr.getPendingWorkRequests(), Eq(0));
}

TEST_F(MgrWorkQueue_F, WorkQueueIsOneAfterWorkIsAdded){
	mgr.addWork(work);
	ASSERT_THAT(mgr.getPendingWorkRequests(), Eq(1));
}


TEST(MgrRunning, StartsUpOneThreadWithNoWorkAndFinishesSuccessfully){
	NetworkMapperMgr mgr;
	ASSERT_THAT(mgr.run(1), Eq(TRUE));

}

TEST(NetworkMapperMgr, StartsUpTwoThreadsWithNoWorkAndFinishesSuccessfully){
	NetworkMapperMgr mgr;
	ASSERT_THAT(mgr.run(2), Eq(TRUE));

}

TEST(NetworkMapperMgr, StartsUpAlotOfThreadsWithNoWorkAndFinishesSuccessfully){
	NetworkMapperMgr mgr;
	ASSERT_THAT(mgr.run(2000), Eq(TRUE));

}


class MgrRunWithALotOfWork_F : public Test{
public:
	void SetUp(){
		nworkers = 2;
		nworkItems = 100000;
		for (int i = 0; i < nworkItems; i++){
			std::pair<std::string, int> work{ "host_" + i, 2 };
			mgr.addWork(work);
		}
	}

protected:
	NetworkMapperMgr mgr;
	int nworkers;
	int nworkItems;
};

TEST_F(MgrRunWithALotOfWork_F, StartsUpTwoThreadsWithALotOfWorkAndFinishesSuccessfully){
	ASSERT_THAT(mgr.run(nworkers), Eq(TRUE));

}

TEST_F(MgrRunWithALotOfWork_F, TheNumberOfResultsIsEqualToTheNumberOfQueuedWorkItems){
	mgr.run(nworkers);

	ASSERT_THAT(mgr.getNumberOfResults(), Eq(nworkItems));
}

