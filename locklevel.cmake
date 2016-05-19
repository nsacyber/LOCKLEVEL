function(add_plugin_executable targetName srcPaths pluginPayloadPath)
	add_executable(
		${targetName} 
		${srcPaths})
	
	add_to_payload(${targetName} ${pluginPayloadPath})
	
	
	
	set_target_properties(
		${targetName}
		PROPERTIES
		LINK_FLAGS "/pdbaltpath:${PROJECT_NAME}.pdb")

endfunction(add_plugin_executable)

function(add_to_payload targetName pluginPayloadPath)
	add_custom_command(
		TARGET ${targetName}
		POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:${targetName}>" "${pluginPayloadPath}")

endfunction(add_to_payload)


