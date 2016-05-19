
set(NETWORKMAPPERLIB_HOME "NetworkMapperLib")
set(NETWORKMAPPER_DRIVER_HOME "NetworkMapper_driver")

add_library(NetworkMapperLib STATIC
	"${NETWORKMAPPERLIB_HOME}/NetworkUtil.cpp" 
	"${NETWORKMAPPERLIB_HOME}/TargetResults.cpp"
	"${NETWORKMAPPERLIB_HOME}/TargetResultsTcp.cpp")
	
	
add_executable(NetworkMapper_driver 
	"${NETWORKMAPPER_DRIVER_HOME}/main.cpp")

target_link_libraries(NetworkMapper_driver NetworkMapperLib)

add_dependencies(NetworkMapper_driver NetworkMapperLib)




install(TARGETS NetworkMapper_driver NetworkMapperLib
	ARCHIVE DESTINATION "lib"
	LIBRARY DESTINATION "lib"
	RUNTIME DESTINATION "bin")