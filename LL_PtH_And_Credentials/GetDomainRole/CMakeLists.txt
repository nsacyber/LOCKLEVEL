#GetDomainRole makefile
cmake_minimum_required (VERSION 3.2)
project(GetDomainRole)

set(GETDOMAINROLE_PROJ_HOME "GetDomainRole")

if(${IS_32BIT_BUILD})
	set(t_GetDomainRole "GetDomainRole")

	add_plugin_executable(
		${t_GetDomainRole}
		"${GETDOMAINROLE_PROJ_HOME}/main.cpp"
		"${PTH_PLUGIN_PAYLOAD_HOME}")
		
endif()

