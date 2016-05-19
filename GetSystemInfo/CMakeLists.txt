#GetSystemInfo makefile
cmake_minimum_required (VERSION 3.2)
project(GetSystemInfo)

set(GET_SYSTEM_INFO_PROJ_HOME "GetSystemInfo")


if(${IS_32BIT_BUILD})
	set(t_GetSystemInfo "GetSystemInfo")

	add_plugin_executable(
		${t_GetSystemInfo}
		"${GET_SYSTEM_INFO_PROJ_HOME}/GetSystemInfo.cpp"
		"${PTH_PLUGIN_PAYLOAD_HOME}")
	
	add_to_payload(${t_GetSystemInfo} "${AV_PLUGIN_PAYLOAD_HOME}")
	add_to_payload(${t_GetSystemInfo} "${AW_PLUGIN_PAYLOAD_HOME}")
	add_to_payload(${t_GetSystemInfo} "${HIPS_PLUGIN_PAYLOAD_HOME}")
	add_to_payload(${t_GetSystemInfo} "${OS_PLUGIN_PAYLOAD_HOME}")
	add_to_payload(${t_GetSystemInfo} "${OSPH_PLUGIN_PAYLOAD_HOME}")
	add_to_payload(${t_GetSystemInfo} "${AE_PLUGIN_PAYLOAD_HOME}")
	
	target_link_libraries(${t_GetSystemInfo} "xmllite.lib" "wbemuuid.lib" "ws2_32.lib" "dnsapi.lib")
	
endif()

	






	
	
	
	
