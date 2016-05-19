#include <gmock/gmock.h>

#pragma comment(lib, "gmock.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "NetworkMapper.lib")

int main(int argc, char* argv[]){
	::testing::InitGoogleMock(&argc, argv);
	return RUN_ALL_TESTS();
}