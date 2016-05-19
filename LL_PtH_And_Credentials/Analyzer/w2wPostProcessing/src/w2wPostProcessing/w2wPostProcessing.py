import argparse
import os
import pdb

EXIT_SUCCESS = 0
EXIT_FAILURE = 1

W2W_RESULTS_EXT = ".w2w"
ROLE_RESULTS_EXT = ".role"

class InvalidTargetResultFormatError(Exception):
    pass

class InvalidRoleResultFormatError(Exception):
    pass

def enum(**named_values):
    return type('Enum', (), named_values)

OSType = enum(WORKSTATION="WORKSTATION", 
              SERVER="SERVER", 
              DOMAIN_CONTROLLER="DC", 
              UNKNOWN="UNKNOWN")

osTypes = set([OSType.WORKSTATION,
              OSType.SERVER,
              OSType.DOMAIN_CONTROLLER,
              OSType.UNKNOWN])



def getFilesByExtension(rootDir, extension):
    return [os.path.abspath(os.path.join(rootDir, filename)) for filename in os.listdir(rootDir) \
            if os.path.isfile(os.path.join(rootDir, filename)) \
            and filename.endswith(extension)]



def isComment(s):
    return s.startswith("#")


def isWorkstation(d, host):
    try:
        return d[host] == OSType.WORKSTATION
    except KeyError:
        return False
    
def isServer(d, host):
    try:
        return d[host] == OSType.SERVER or d[host] == OSType.DOMAIN_CONTROLLER
    except KeyError:
        return False
    
def isDomainController(d, host):
    try:
        return d[host] == OSType.DOMAIN_CONTROLLER
    except KeyError:
        return False

def computeOpenPaths(lstOfHostResultDicts):
    #get all open paths
    openPaths = []
    for hostResult in lstOfHostResultDicts:
        openPaths.extend([key for key, val in hostResult.items() if val])
        
    return openPaths

def isW2WCommunication(src, dst, hostToTypeMapping):
    return isWorkstation(hostToTypeMapping, src) and isWorkstation(hostToTypeMapping, dst)
    
    
    
    
class W2WPostProcessor(object):
    def __init__(self, w2wResultFilenames=None, roleResultFilenames=None):
        if w2wResultFilenames is None:
            self.w2wResultFilenames = getFilesByExtension(os.curdir, W2W_RESULTS_EXT)
        else:
            self.w2wResultFilenames = w2wResultFilenames
            
        if roleResultFilenames is None:
            self.roleResultFilenames = getFilesByExtension(os.curdir, ROLE_RESULTS_EXT)
        else:
            self.roleResultFilenames = roleResultFilenames
            
            
    def process(self):
        hostnameToOSTypeMapping = RoleResultParser.parseRoleResults(self.roleResultFilenames)
    
        lstOfHostResultDicts = HostResultParser.parseHostResults(self.w2wResultFilenames)
    
        openPaths = computeOpenPaths(self.lstOfHostResultDicts)
        
        #only accept (src,dst) where src.type == WORKSTATION and dst.type == WORKSTATION
        w2wOpenPaths = [(srcHost, dstHost, port) for srcHost, dstHost, port in openPaths \
                            if isW2WCommunication(srcHost, dstHost, hostnameToOSTypeMapping)]
        
        
        
        return ''.join(["%s,%s,%s\n" % (srcHost, dstHost, port) for srcHost, dstHost, port in w2wOpenPaths])


    def getHostResults(self):
        return HostResultParser.parseHostResults(self.w2wResultFilenames)
    
    
    def getPaths(self):
        hostResults = self.getHostResults() 
        paths = []
        for host in hostResults:
            paths.extend(host.keys())
        return paths


    
    
    def getRoleResults(self):
        return RoleResultParser.parseRoleResults(self.roleResultFilenames)
        
        
        
    
    
class HostResultParser(object):
    @staticmethod
    def parseHostResults(lstOfFilenames):
        results = []
        for filename in lstOfFilenames:
            results.append(HostResultParser.parseHostResult(filename))
            
            
        return results

    @staticmethod
    def parseHostResult(filename):
        results = {}
        with open(filename, 'rb') as f:
            lines = f.readlines()
     
            for targetResult in lines:
                tr = TargetResultParser.parse(targetResult)
                if tr is None:
                    continue
    
                srcHost, dstHost, port, success = tr.toTuple()
                results[(srcHost, dstHost, port)] = success
                
        return results
        

class TargetResultParser(object):
    @staticmethod
    def parse(s):
        try:
            return TargetResult(s)
        except InvalidTargetResultFormatError:
            return None
        
class TargetResult(object):
    def __init__(self, s):
        if not self._isTargetResult(s):
            raise InvalidTargetResultFormatError()
        self.srcHost, self.dstHost, self.port, self.success = self.parse(s)
    
    def _isInProperFormat(self, s):
        #csv format with 4 elements
        return s.count(',') == 3
    
    def _isTargetResult(self, result):
        return \
            (not isComment(result)) and \
            (not result.isspace()) and \
            (self._isInProperFormat(result))
   

    def parse(self, s):
        
        srcHost, dstHost, port, success = s.split(',')
        
        
        return srcHost.lower().strip(), dstHost.lower().strip(), port.strip(), success.strip()


    def toTuple(self):
        return self.srcHost, self.dstHost, self.port, self.success




class RoleResultParser(object):
    @staticmethod
    def parseRoleResults(lstOfFilenames):
        global osTypes
        
        results = {}
        for filename in lstOfFilenames:
            roleResult = RoleResultParser.parseRoleResult(filename)
            if roleResult is None:
                print "error parsing role result of %s" % filename
                continue
            
            if roleResult.role not in osTypes:
                print "Found unknown domain role of %s" % str(roleResult)
                continue 
            
            hostname, productType = roleResult.toTuple()
            
            #only for now, while hostname is not a fqdn
            results[hostname] = productType
            
        return results
    

    @staticmethod    
    def parseRoleResult(filename):
        with open(filename, 'rb') as f:
            roleResultInput = ''.join([line for line in f.readlines()])
            return RoleResultParser.parse(roleResultInput)
    
    
    @staticmethod
    def parse(s):
        try:
            return RoleResult(s)
        except InvalidRoleResultFormatError:
            return None


class RoleResult(object):
    def __init__(self, s):
        if not self._isRoleResult(s):
            raise InvalidRoleResultFormatError()
        
        self.hostname, self.role = self.parse(s)
        
    def parse(self, s):
        hostname, roleResult = s.split("=")
        return hostname.lower().strip(), roleResult.strip()
        
    
    def _isRoleResult(self,s):
        #format is: only 1 line and in 'a=b'
        return len(s.split()) == 1 and len(s.split("=")) == 2
    
    
    def toTuple(self):
        return self.hostname, self.role
    
    def __str__(self):
        return "(Hostname=%s,Role=%s)" % (self.hostname, self.role)
        



    
def main(w2ws, roles):
    w2wpp = W2WPostProcessor(w2ws, roles)
    print w2wpp.process()
    
    


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-w2w', nargs='+', type=str)
    parser.add_argument('-role', nargs='+', type=str)
    args = parser.parse_args()
    
    main(args.w2w, args.role)


