import argparse
import sys
import os
import pdb

import path
import mitigation
import remediation
import penalty
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom

def isLoop(src, dst):
    return src == dst or dst.find(src) != -1

def addPenalties(paths, report):
    for p in paths:
        if isLoop(p.src, p.dst):
            #currently the tool that does the port mapping just tries every host on the domain
            #include the one it is currently on
            continue
        if not p.dst in report:
            #this shouldn't happen
            pdb.set_trace()
            raise Exception
            
            #if report doesn't exist yet create it
            report[p.dst] = mitigation.Mitigation("Pass-the-Hash", p.dst)
            
        #add penalty
        report[p.dst].addPenalty(penalty.W2W_CommunicationPenalty(p.src, 
                                                                  p.dst, 
                                                                  p.port))
        
class W2WAnalyzer(object):
    def __init__(self, paths, roles):
        self.paths = filter(lambda x: x is not None, [path.Path.create(s) for s in paths])
        self.hosts = set(self._getHostsFromPaths(self.paths))
        self.roles = roles
        self.reports = None
        
    def _getHostsFromPaths(self, paths):
        return set([curPath.src for curPath in paths]).union(set([curPath.dst for curPath in paths]))
        
    def _generateReports(self):
        hostToMitigationReport = {}
        for host in self.hosts:
            hostToMitigationReport[host] = mitigation.Mitigation("Pass-the-Hash", host)
        
        
        addPenalties(self.paths, hostToMitigationReport)
        
        return hostToMitigationReport
        
    def analyze(self):
        self.reports = self._generateReports()
        
            
    def write(self, f):
        for hostname, report in self.reports:
            with open("LL_Pth_W2W_%s.w2wpp" % hostname, "wb") as g:
                reparsed = minidom.parseString(ET.tostring(report.toElement()))
                g.write(reparsed.toprettyxml(indent="\t"))


def main(openPathsFilename):
    openPaths = None
    with open(openPathsFilename, 'rb') as f:
        openPaths = f.readlines()
        
    w2wAnalyzer = W2WAnalyzer(openPaths)
    w2wAnalyzer.analyze()
    with open('allHostW2wScores2.xml', 'wb') as f:
        w2wAnalyzer.write(f)
    
#===============================================================================
#     #if input is nothing but whitespace, then Path.create returns None.
#     #filter those out
#     paths = filter(lambda x: x is not None, [path.Path.create(s) for s in openPaths])
#     
#     reports = generateReports(paths)
#     
#     
#     top = ET.Element("network")
#     for report in reports:
#         report.toElement(parent=top)
#             
# 
#     with open('allHostW2wScores.xml', 'wb') as f:
#         rawXmlAsString = ET.tostring(top)
#         reparsed = minidom.parseString(rawXmlAsString)
#         f.write(reparsed.toprettyxml(indent="\t"))
#===============================================================================
        

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("openPathsFilename")
    args = parser.parse_args()
    main(args.openPathsFilename)