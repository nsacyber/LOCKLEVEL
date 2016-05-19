#GetAVStatus makefile
cmake_minimum_required (VERSION 3.2)
project(GetAVStatus)


set(GET_AV_STATUS_HOME ${PROJECT_NAME})

if(${IS_32BIT_BUILD})
	add_executable(GetAVStatus 
		"${GET_AV_STATUS_HOME}/GetAVStatus.cpp")


	target_link_libraries(GetAVStatus "xmllite.lib" "ws2_32.lib" "dnsapi.lib" )

	set_target_properties(GetAVStatus
		PROPERTIES
		LINK_FLAGS "/pdbaltpath:${PROJECT_NAME}.pdb")

	add_custom_command(TARGET GetAVStatus POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:GetAVStatus> "${AV_PLUGIN_PAYLOAD_HOME}")
endif()

