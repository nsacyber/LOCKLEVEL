var pluginNameMap = [
	{name:'Pass-the-Hash', display:'Pass-the-Hash'},
	{name:'AntiExploitation', display:'Anti-Exploitation'}, 
	{name:'AW', display:'Application Whitelisting'}, 
	{name:'AVFileReputation', display:'Anti-Virus File Reputation'}, 
	{name:'HBSS', display:'Host Intrusion Prevention'}, 
	{name:'OperatingSystem', display:'Operating System Version'}, 
	{name:'OperatingSystemPatchHealth', display: 'Operating System Patch Health'}
	];

// get the nice display name based on the internal plugin name used in scoremaster
function getPluginDisplayName(plugin) {
	var displayText = '';
	
	if (typeof plugin !== "undefined" && plugin != null) {
		for(var index=0; index < pluginNameMap.length; index++) {
			var item = pluginNameMap[index];
			if(item.name == plugin) {
				displayText = item.display;
				break;
			}
		}
	}
	
	return displayText;
}
	
// get plugin score for a specific plugin for a specific system
function getSystemInformation(system) {
	var sysinfo = scoreData.systems[system].sysinfo;

	return [
		sysinfo.hostName, // string
		sysinfo.domainName, // string
		sysinfo.ip4Address, // string
		sysinfo.ip6Address, // string
		sysinfo.macAddress, // string
		sysinfo.productType // string
	];
}

function getFullSystemInformationWithDescription(system) {
	var sysinfo = scoreData.systems[system].sysinfo;
	
	return [
		['Host', sysinfo.hostName],
		['Domain', sysinfo.domainName],
		['IPv4', sysinfo.ip4Address],
		['IPv6', sysinfo.ip6Address],
		['MAC', sysinfo.macAddress],
		['Date', sysinfo.timeStamp], // int
		['OS', sysinfo.osName],
		['OS Version', sysinfo.osVersion],
		['OS SP', sysinfo.servicePack],
		['Role', sysinfo.productType],
		['OS Arch', sysinfo.osArch],
		['Hardware Arch', sysinfo.hardArch]
	];
}

// get overall system score
function getSystemScore(system) {
	return scoreData.systems[system].scores.base; //decimal
}

// get specific plugin score for a system
function getPluginScore(system, plugin) {
	return scoreData.systems[system].scores.plugins[plugin]; // decimal
}

// get plugin scores for a system
function getPluginScores(system) {
	return scoreData.systems[system].scores.plugins; // object of  { "pluginname": score }
}

//get overall plugin score for the network
function getPluginNetworkScore(plugin) {
   return scoreData.scores.plugins[plugin]
}

// get overall score for the network
function getNetworkScore() {
   return scoreData.scores.base
}

// gets the list of remediations by ID that are found on the network along with the projected score if the remediation is fixed
function getRemediationScoreByID(rem){
	return[
	rem,
	scoreData.remediation_scores[rem]
	];
}

function getParameterByName(name) {
	name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
	var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
		results = regex.exec(location.search);
	return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
}

// get html for making a header
// score is optional so to leave out score just pass in null
function makeHeader(title, document, score) {
	document.title = 'LOCKLEVEL - ' + title;
	
	var scoreText = ''
	
	if (typeof score !== "undefined" && score != null && score > 0) {
		scoreText = parseFloat(score).toFixed(1)
	}

	return 	'<p style="text-align: left; font-size: 24px;">' + title + ' Score: ' + scoreText + '</p>';
}