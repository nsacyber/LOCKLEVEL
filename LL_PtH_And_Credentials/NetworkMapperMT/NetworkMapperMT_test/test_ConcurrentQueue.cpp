#include <gmock/gmock.h>
#include "../NetworkMapperMT/ConcurrentQueue.h"



using namespace testing;

class ConcurrentQueueEmpty_F :public Test{
protected:
	ConcurrentQueue<int> cq;


};

TEST_F(ConcurrentQueueEmpty_F, IsEmptyInitially){
	ASSERT_THAT(cq.empty(), Eq(TRUE));
}



class ConcurrentQueuePush_F :public Test{
protected:
	ConcurrentQueue<int> cq;


};

TEST_F(ConcurrentQueuePush_F, IsNotEmptyAfterEnqueue){
	cq.push(2);

	ASSERT_THAT(cq.empty(), Eq(FALSE));
}

TEST(ConcurrentQueueSize, SizeIsInitiallyZero){
	ConcurrentQueue<int> cq{};

	ASSERT_THAT(cq.size(), Eq(0));
}

TEST(ConcurrentQueueSize, SizeIsOneAfterPush){
	ConcurrentQueue<int> cq{};
	cq.push(12);
	ASSERT_THAT(cq.size(), Eq(1));
}


TEST(ConcurrentQueuePop, GetsTheFirstElementWhenOnlyOneIsInTheQueue){
	ConcurrentQueue<int> cq{};
	cq.push(12);
	
	ASSERT_THAT(cq.pop(), Eq(12));
}


