
#include <gmock/gmock.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <vector>
#include "../NetworkMapperLib/NetworkUtil.h"


#include "../NetworkMapperLib/TargetResults.h"
#include "../NetworkMapperLib/TargetResultsTcp.h"

using namespace testing;
using namespace NetworkUtil;




void ensureWsaCleanedUp(){
	while (NetworkUtil::WSAUninitialize() == 0);
}

class NetworkUtil_WsaUninitialized_F :public Test{
	void SetUp(){
		ensureWsaCleanedUp();
	}

	void TearDown(){
		ensureWsaCleanedUp();

	}
};

TEST_F(NetworkUtil_WsaUninitialized_F, WsaIsUninitializedByDefault){
	ASSERT_THAT(NetworkUtil::isWsaInitialized(), Eq(FALSE));
}

TEST_F(NetworkUtil_WsaUninitialized_F, WsaIsInitializedAfterACallToWsaInitialize){
	NetworkUtil::WSAInitialize();
	ASSERT_THAT(NetworkUtil::isWsaInitialized(), Eq(TRUE));
}

TEST_F(NetworkUtil_WsaUninitialized_F, WsaUninitializeIsTheInverseOfWsaInitialize){
	ASSERT_THAT(NetworkUtil::isWsaInitialized(), Eq(FALSE));

	NetworkUtil::WSAInitialize();
	ASSERT_THAT(NetworkUtil::isWsaInitialized(), Eq(TRUE));
	
	NetworkUtil::WSAUninitialize();
	ASSERT_THAT(NetworkUtil::isWsaInitialized(), Eq(FALSE));
}


class NetworkUtil_WsaInitialized_F : public Test{
	void SetUp(){
		ensureWsaCleanedUp();
		NetworkUtil::WSAInitialize();
	}

	void TearDown(){
		ensureWsaCleanedUp();

	}

protected:
	std::string hostname;


};

TEST_F(NetworkUtil_WsaInitialized_F, ResolveOutResultsIsAnAddrinfoForSomeIp){
	hostname = "127.0.0.1";
	ADDRINFOA* results;
	NetworkUtil::resolve(hostname, 80, &results);

	ASSERT_THAT(results, Ne((ADDRINFOA*)NULL));
}

TEST_F(NetworkUtil_WsaInitialized_F, HostIsAccessibleViaTcp){
	hostname = "127.0.0.1";
	ASSERT_THAT(NetworkUtil::isHostAccessibleTcp(hostname, 135), Eq(TRUE));
}


TEST_F(NetworkUtil_WsaInitialized_F, HostIsAccessibleViaTcpGivenAListOfPorts){
	hostname = "127.0.0.1";
	std::vector<int> ports = { 1, 135, 139, 445 };
	ASSERT_THAT(NetworkUtil::isHostAccessibleTcp(hostname, ports), Eq(TRUE));
}

class NetworkMapper_WsaUninitialized_F : public Test{
	void SetUp(){
		//need this to ensure that constructor gets called for mapper, which will initialize wsa
		ensureWsaCleanedUp();
	}

	void TearDown(){

		ensureWsaCleanedUp();
	}

};

TEST_F(NetworkMapper_WsaUninitialized_F, InitializationWithWsaNotInitializedHasAHostnameAsTheEmptyString){
	NetworkMapper mapper{};
	ASSERT_THAT(mapper.getHostname(), Eq(""));
}

class NetworkMapper_WsaInitialized_F : public Test{
	void SetUp(){
		ensureWsaCleanedUp();
		NetworkUtil::WSAInitialize();
	}

	void TearDown(){
		ensureWsaCleanedUp();

	}
};

TEST_F(NetworkMapper_WsaInitialized_F, HostnameIsCorrectUponNetworkMapperInitializationSuccess){
	std::string hostname = "w81x64-dev.test.net";
	NetworkMapper m{};

	ASSERT_THAT(m.getHostname(), Eq(hostname));
}



class NetworkMapper_WsaInitialized_WithMapper_F : public Test{
	void SetUp(){
		//need this to ensure that constructor gets called for mapper, which will initialize wsa
		ensureWsaCleanedUp();
		NetworkUtil::WSAInitialize();
		mapper = NetworkMapper();
	}

	void TearDown(){
		ensureWsaCleanedUp();
		
	}

protected:
	NetworkMapper mapper;
	std::string hostname;


};



TEST_F(NetworkMapper_WsaInitialized_WithMapper_F, MapLoopbackOpenTcpPorts){
	hostname = "127.0.0.1";
	std::vector<int> ports = { 1, 135, 139, 445 };

	TargetResultsTcp result = mapper.mapTargetTcp(hostname, ports);

	ASSERT_THAT(result.getOpenPorts().size(), Eq(2));
	ASSERT_THAT(result.get(ports.at(0)), Eq(FALSE));
	ASSERT_THAT(result.get(ports.at(1)), Eq(TRUE));
	ASSERT_THAT(result.get(ports.at(2)), Eq(FALSE));
	ASSERT_THAT(result.get(ports.at(3)), Eq(TRUE));
}



TEST_F(NetworkMapper_WsaInitialized_WithMapper_F, MapLocalhostOpenTcpPorts){
	hostname = "192.168.85.128";
	std::vector<int> ports = { 1, 135, 139, 445 };

	TargetResultsTcp result = mapper.mapTargetTcp(hostname, ports);

	ASSERT_THAT(result.getOpenPorts().size(), Eq(3));
	ASSERT_THAT(result.get(ports.at(0)), Eq(FALSE));
	ASSERT_THAT(result.get(ports.at(1)), Eq(TRUE));
	ASSERT_THAT(result.get(ports.at(2)), Eq(TRUE));
	ASSERT_THAT(result.get(ports.at(3)), Eq(TRUE));

}


TEST_F(NetworkMapper_WsaInitialized_WithMapper_F, MapHostnameOpenTcpPorts){
	//get hostname
	char computername[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
	DWORD computernameLen = _countof(computername);
	ASSERT_THAT(GetComputerNameA(computername, &computernameLen), Eq(TRUE));

	hostname = std::string(computername);
	std::vector<int> ports = { 1, 135, 139, 445 };

	TargetResultsTcp result = mapper.mapTargetTcp(hostname, ports);

	ASSERT_THAT(result.getOpenPorts().size(), Eq(3));
	ASSERT_THAT(result.get(ports.at(0)), Eq(FALSE));
	ASSERT_THAT(result.get(ports.at(1)), Eq(TRUE));
	ASSERT_THAT(result.get(ports.at(2)), Eq(TRUE));
	ASSERT_THAT(result.get(ports.at(3)), Eq(TRUE));
}


class NetworkMapper_MapNeighbor_F : public Test{
	void SetUp(){
		ensureWsaCleanedUp();
		NetworkUtil::WSAInitialize();
		mapper = NetworkMapper{};
	}

	void TearDown(){
		ensureWsaCleanedUp();

	}
protected:
	std::string hostname;
	NetworkMapper mapper;
	std::vector<int> ports;
};

TEST_F(NetworkMapper_MapNeighbor_F, ReturnsATargetResultWithCorrectNumberOfOpenPorts){
	hostname = "127.0.0.1";
	
	ports = std::vector<int>{ 1, 135, 139, 445 };

	TargetResults targetResult = mapper.mapNeighbor(hostname, ports);

	ASSERT_THAT(targetResult.getTcpResults().getOpenPorts().size(), Eq(2));
}


class NetworkMapper_MapNeighbors_F : public Test{
	void SetUp(){
		ensureWsaCleanedUp();
		NetworkUtil::WSAInitialize();
		mapper = NetworkMapper{};
	}

	void TearDown(){
		ensureWsaCleanedUp();

	}
protected:
	std::vector<std::string> hostnames;
	NetworkMapper mapper;
	std::vector<int> ports;
};

TEST_F(NetworkMapper_MapNeighbors_F, MapNeighborsWithNoHostnamesReturnsZeroResults){
	ports = std::vector<int>{ 12346, 135, 139, 445 };

	mapper.mapNeighbors(hostnames, ports);

	ASSERT_THAT(mapper.getResults().size(), Eq(0));
}

TEST_F(NetworkMapper_MapNeighbors_F, MapNeighborsReturnsOneResultForOneNeighbor){
	hostnames = { "127.0.0.1" };
	ports = { 1, 135, 139, 445 };

	mapper.mapNeighbors(hostnames, ports);

	ASSERT_THAT(mapper.getResults().size(), Eq(1));
}

TEST_F(NetworkMapper_MapNeighbors_F, MapNeighborsReturnsMultipleResultsForMultipleNeighbor){
	hostnames = { "127.0.0.1", "127.0.0.1", "127.0.0.1" };
	ports = { 1, 135, 139, 445 };

	mapper.mapNeighbors(hostnames, ports);

	ASSERT_THAT(mapper.getResults().size(), Eq(hostnames.size()));
}


TEST_F(NetworkMapper_MapNeighbors_F, ToStringWithOneTargetResultWithOneTcpPortTested){
	hostnames = { "127.0.0.1" };
	ports = { 135 };

	mapper.mapNeighbors(hostnames, ports);

	ASSERT_THAT(mapper.toString(), Eq("w81x64-dev.test.net,127.0.0.1,135,1\n"));
}


TEST_F(NetworkMapper_MapNeighbors_F, ToStringWithOneTargetResultWithTwoTcpPortsTestedAccessible){
	hostnames = { "127.0.0.1" };
	ports = { 445, 135 };

	mapper.mapNeighbors(hostnames, ports);

	ASSERT_THAT(mapper.toString(), Eq("w81x64-dev.test.net,127.0.0.1,135,1\nw81x64-dev.test.net,127.0.0.1,445,1\n"));
}

TEST_F(NetworkMapper_MapNeighbors_F, ToStringWithTwoTargetResultsWithOneTcpPortTested){
	hostnames = { "127.0.0.1", "w81x64-dev.test.net" };
	ports  = { 139 };

	mapper.mapNeighbors(hostnames, ports);

	ASSERT_THAT(mapper.toString(), Eq("w81x64-dev.test.net,127.0.0.1,139,0\nw81x64-dev.test.net,w81x64-dev.test.net,139,1\n"));
}
TEST_F(NetworkMapper_MapNeighbors_F, ToStringWithTwoTargetResultsWithTwoTcpPortsTested){
	hostnames = { "127.0.0.1", "w81x64-dev.test.net" };
	ports = { 139, 135 };

	mapper.mapNeighbors(hostnames, ports);

	ASSERT_THAT(mapper.toString(), Eq("w81x64-dev.test.net,127.0.0.1,135,1\nw81x64-dev.test.net,127.0.0.1,139,0\nw81x64-dev.test.net,w81x64-dev.test.net,135,1\nw81x64-dev.test.net,w81x64-dev.test.net,139,1\n"));
}

TEST_F(NetworkMapper_MapNeighbors_F, OperatorPutToWithTwoTargetResultsWithTwoTcpPortsTested){
	hostnames = { "127.0.0.1", "w81x64-dev.test.net" };
	ports = { 139, 135 };

	mapper.mapNeighbors(hostnames, ports);
	std::ostringstream actualOss;
	NetworkUtil::operator<<(actualOss, mapper);

	std::string actualString{ actualOss.str() };


	ASSERT_THAT(actualString, Eq("w81x64-dev.test.net,127.0.0.1,135,1\nw81x64-dev.test.net,127.0.0.1,139,0\nw81x64-dev.test.net,w81x64-dev.test.net,135,1\nw81x64-dev.test.net,w81x64-dev.test.net,139,1\n"));
}


TEST_F(NetworkMapper_WsaInitialized_WithMapper_F, ToStringWithZeroTargetResultsIsTheEmptyString){
	ASSERT_THAT(mapper.toString(), Eq(""));
}

