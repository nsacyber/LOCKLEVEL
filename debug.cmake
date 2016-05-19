#function(printAllVariables)
#get_cmake_property(_variableNames VARIABLES)
#foreach(_variableName ${_VARIABLENAMES})
	

#endfunction(printAllVariables)

function(DBGPRINT msg)
	
	MESSAGE(STATUS ${msg})

endfunction(DBGPRINT)

function(DBGPRINT_VAR _variableName)
	DBGPRINT("***DEBUG***: ${_variableName}=${${_variableName}}")

endfunction(DBGPRINT_VAR)