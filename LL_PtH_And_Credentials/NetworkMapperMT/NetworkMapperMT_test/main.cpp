#include <gmock/gmock.h>

#pragma comment(lib, "gmock.lib")
#pragma comment(lib, "NetworkMapperMT.lib")

int main(int argc, char* argv[]){
	::testing::InitGoogleMock(&argc, argv);
	return RUN_ALL_TESTS();
}