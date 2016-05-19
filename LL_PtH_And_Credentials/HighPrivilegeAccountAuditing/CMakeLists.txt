#HighPrivilegeAccountUsage makefile
cmake_minimum_required (VERSION 3.2)
project(HighPrivilegeAccountAuditing)

set(HIGH_PRIVILEGE_ACCOUNT_AUDITING_PROJ_HOME "HighPrivilegeAccountAuditing")

if(${IS_32BIT_BUILD})
	#targets
	set(t_HighPrivilegeAccountAuditing "HighPrivilegeAccountAuditing")
	#end targets


	add_plugin_executable(
		${t_HighPrivilegeAccountAuditing} 
		"${HIGH_PRIVILEGE_ACCOUNT_AUDITING_PROJ_HOME}/Source.cpp" 
		"${PTH_PLUGIN_PAYLOAD_HOME}")
		
	target_link_libraries(${t_HighPrivilegeAccountAuditing} "Activeds.lib" "ADSIid.lib" "netapi32.lib" "advapi32.lib")
endif()

