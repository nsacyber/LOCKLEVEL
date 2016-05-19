import xml.etree.cElementTree as ET
import json
import os

import traceback
import systemInfo
import pdb

from w2wPostProcessing import RoleResultParser

hostnameToOSTypeMapping = None


def getFilesByExtension(rootDir, extension):
	return [os.path.abspath(os.path.join(rootDir, filename)) for filename in os.listdir(rootDir) \
			if os.path.isfile(os.path.join(rootDir, filename)) \
			and filename.endswith(extension)]
	
	
def getFilesByExtensionFromDirs(rootDirs, extension):
	results = []
	for rootDir in rootDirs:
		results.extend(getFilesByExtension(rootDir, extension))
		
	return results


def getCurrentUser():
	return os.environ.get("USERNAME")

def isCurrentUser(username):
	return username.lower() == getCurrentUser().lower() 

W2W_RESULTS_EXT = ".w2w"
ROLE_RESULTS_EXT = ".role"
SYSTEMINFO_RESULTS_EXT = ".systeminfo"
HPAU_RESULTS_EXT = ".hpau"
ZIP_EXT = ".zip"


PENALTIES = {
	'UPGRADE_OS': {
		'id': 'UPGRADE_OS',
		'name': 'Upgrade OS to newer than Windows XP',
		'value': 100,
		'reason': {
			'text': 'Event Auditing is not available in Windows XP'
		},
		'remediation': {
			'id': 'UPGRADE_OS',
			'text': 'Upgrade the operating system to be newer than Windows XP'
		}
	},
	'CONFIGURE_EVENT_LOG': {
		'id': 'CONFIGURE_EVENT_LOG',
		'name': 'Configure logon/logoff auditing',
		'value': 100,
		'reason': {
			'text': 'Group Policy is not configured to audit user logon/logoff events'
		},
		'remediation': {
			'id': 'CONFIGURE_EVENT_LOG',
			'text': 'Configure Group Policy to audit user logon/logoff events'
		}
	},
	'DOMAIN_ADMIN_LOGON_ON_WORKSTATION': lambda name: {
		'id': 'DOMAIN_ADMIN_LOGON_WORKSTATION',
		'name': 'Domain Admin (' + name + ') logon to workstation',
		'value': 10,
		'reason': {
			'text': 'Domain Admin (' + name + ') logged into this workstation. This allows attackers to steal Domain Admin credentials for re-use on other systems.'
		},
		'remediation': {
			'id' : 'DOMAIN_ADMIN_LOGON_REMEDIATION_WORKSTATION',
			'text': 'Do not use Domain Admin accounts on workstations.'
		}
	},
	'DOMAIN_ADMIN_LOGON_ON_SERVER': lambda name: {
		'id': 'DOMAIN_ADMIN_LOGON_SERVER',
		'name': 'Domain Admin (' + name + ') logon to member server',
		'value': 1,
		'reason': {
			'text': 'Domain Admin (' + name + ') logged into this member server. This potentially allows attackers to steal Domain Admin credentials for re-use on other systems.'
		},
		'remediation': {
			'id' : 'DOMAIN_ADMIN_LOGON_REMEDIATION_SERVER',
			'text': 'Do not use Domain Admin accounts on member servers.'
		}
	}	
}


def createPenalty(root, penalties, penalty, *args):
	if callable(penalty):
		penalty = penalty(*args)
	penalties.append(penalty['value'])
	p = ET.SubElement(root, 'penalty')
	for k, v in penalty.items():
		if k in ['reason', 'remediation']:
			continue
		p.set(k, str(v))
	if 'reason' in penalty:
		reason = ET.SubElement(p, 'reason')
		for k, v in penalty['reason'].items():
			if k == "text":
				reason.text = str(v)
			else:
				reason.set(k, str(v))
	if 'remediation' in penalty:
		remediation = ET.SubElement(p, 'remediation')
		for k, v in penalty['remediation'].items():
			if k == "text":
				remediation.text = str(v)
			else:
				remediation.set(k, str(v))

def jsonToXml(filename, host):
	global hostnameToOSTypeMapping
	penalties = []
	with open(filename) as f:
		mitigation = ET.Element("mitigation")
		score = ET.SubElement(mitigation, "score")
		input_ = None
		try:
			input_ = json.loads(f.read())
		except ValueError:
			print "***Warning: no data in %s" % filename
			score.set('cumulativeScore', str(1))
			return mitigation
			
	
		if input_.get('error', None):
			if input_['error'] == "Failed to load wevtapi.dll":
				createPenalty(score, penalties, PENALTIES['UPGRADE_OS'])
			else:
				createPenalty(score, penalties, PENALTIES['CONFIGURE_EVENT_LOG'])
		else:
			
			for logon in input_.get('logons', []):
				
				penalty = None
				
				if hostnameToOSTypeMapping[host] == "WORKSTATION":
					penalty = PENALTIES['DOMAIN_ADMIN_LOGON_ON_WORKSTATION']
					
				elif hostnameToOSTypeMapping[host] == "SERVER":
					penalty = PENALTIES['DOMAIN_ADMIN_LOGON_ON_SERVER']
					
				if penalty is not None:
					for i in xrange(int(logon["count"])):					
						createPenalty(score, penalties, penalty(logon['name']))
					
					
				#createPenalty(score, penalties, PENALTIES['DOMAIN_ADMIN_LOGON_ON_SERVER'](logon['name']))
		
		cumulative = 9
		for penalty in penalties:
			c = 100 - penalty
			cumulative = cumulative * (c/100.0)
		cumulative += 1
		cumulative = round(cumulative, 1)
		score.set('cumulativeScore', str(cumulative))
		return mitigation
				
			
		
		
	
	
	
class PrivAnalyzer(object):
	def __init__(self, workingDir):
		self.workingDir = workingDir
		self.reports = {}
		
		
	def analyze(self):
		global hostnameToOSTypeMapping
		hpauResultsFilenames = getFilesByExtensionFromDirs(self.workingDir, HPAU_RESULTS_EXT)
		systemInfoResultsFilenames = getFilesByExtensionFromDirs(self.workingDir, SYSTEMINFO_RESULTS_EXT)
		roleResultFilenames = getFilesByExtensionFromDirs(self.workingDir, ROLE_RESULTS_EXT)
		
		hostnameToOSTypeMapping = RoleResultParser.parseRoleResults(roleResultFilenames)
		hpauResultsFilenames.sort()
		systemInfoResultsFilenames.sort()
		for hpauFilename, systemInfoFilename in zip(hpauResultsFilenames, systemInfoResultsFilenames):
			try:
				sysInfo = systemInfo.SystemInfo.fromFile(systemInfoFilename)
				self.reports[sysInfo.getFqdn().lower()] = jsonToXml(hpauFilename, sysInfo.getFqdn().lower())
			except ValueError:
				print "***Error in privAnalyzer..."
				traceback.print_exc()
				

		
		
		