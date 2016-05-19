import pdb
import sys
import argparse
import os
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
import traceback

import llExtract
import w2wPostProcessing
import w2wAnalyzer
import privAnalyzer

W2W_RESULTS_EXT = ".w2w"
ROLE_RESULTS_EXT = ".role"
SYSTEMINFO_RESULTS_EXT = ".systeminfo"
HPAU_RESULTS_EXT = ".hpau"
ZIP_EXT = ".zip"


def computeCompositeScore(listOfScores):
    return sum(listOfScores) / len(listOfScores)


def getFilesByExtension(rootDir, extension):
    return [os.path.abspath(os.path.join(rootDir, filename)) for filename in os.listdir(rootDir) \
            if os.path.isfile(os.path.join(rootDir, filename)) \
            and filename.endswith(extension)]
    
    
def getFilesByExtensionFromDirs(rootDirs, extension):
    results = []
    for rootDir in rootDirs:
        results.extend(getFilesByExtension(rootDir, extension))
        
    return results


def getExtractedZipDirs(zipFilenames):
    result = []
    for zipFilename in zipFilenames:
        pathToDir, _ = os.path.splitext(zipFilename)
        result.append(pathToDir)
        
    return result

class LL_PthAnalyzer(object):
    def __init__(self, inputDir, outputDir):
        self.inputDir = os.path.abspath(inputDir)

        if not os.path.exists(self.inputDir):
            raise Exception('%s does not exist' % self.inputDir)
        
        
        
        self.outputDir = os.path.abspath(outputDir)
        
        
        
    
    def analyze(self):
        zipFilenames = getFilesByExtension(self.inputDir, ZIP_EXT)
        self._expandPluginOutputFiles(zipFilenames)
        
        zipDirs = getExtractedZipDirs(zipFilenames)
        self._analyze(zipDirs)
        
        
    
            
    
    def _analyze(self, zipDirs):
        self.w2w = self._analyzeW2W(zipDirs)
        self.hpa = self._analyzeHpa(zipDirs)
        
        #get mitigation tags
 
        
        
    def _analyzeHpa(self, zipDirs):
        #high privilege account auditing
        
        analyzer = privAnalyzer.PrivAnalyzer(zipDirs)
        analyzer.analyze()
        return analyzer
        
       
            
    
    def _analyzeW2W(self, zipDirs):
        #workstation to workstation communication
        w2wpp = self._doW2WPostProcessing(zipDirs)
        analyzer = w2wAnalyzer.W2WAnalyzer(w2wpp.getPaths(), w2wpp.getRoleResults())
        analyzer.analyze()
        return analyzer
        
        
        
        
    def _doW2WPostProcessing(self, zipDirs):
        w2wResultsFilenames = getFilesByExtensionFromDirs(zipDirs, W2W_RESULTS_EXT)
        roleResultsFilenames = getFilesByExtensionFromDirs(zipDirs, ROLE_RESULTS_EXT)
        
        w2wpp = w2wPostProcessing.W2WPostProcessor(w2wResultsFilenames, roleResultsFilenames)
        return w2wpp
        
    def _expandPluginOutputFiles(self, zipFilenames):
        for zipFilename in zipFilenames:
            if not os.path.exists(zipFilename):
                print "Error %s does not exist" % zipFilename
                continue
            
            extracter = llExtract.LLExtracter(zipFilename)
            extracter.extract()
            
            
    def process(self):
        self.analyze()
        self.buildXml()
        
        
    def buildXml(self):
        if not os.path.exists(self.outputDir):
            os.makedirs(self.outputDir)
        
        
        zipFilenames = getFilesByExtension(self.inputDir, ZIP_EXT)
        
        zipDirs = getExtractedZipDirs(zipFilenames)
        systemInfoFilenames = getFilesByExtensionFromDirs(zipDirs, SYSTEMINFO_RESULTS_EXT)
        
        fqdnToSystemInfo = {}
        for systemInfoFilename in systemInfoFilenames:
            try:
                tree = ET.parse(systemInfoFilename)
                root = tree.getroot()
                fqdn = (root.find("hostName").text + "." + root.find("domainName").text).lower()
                
                fqdnToSystemInfo[fqdn] = root
            except Exception as e:
                traceback.print_exc()
                
            
        
        
        
        for fqdn in fqdnToSystemInfo.keys():
            try:
                hostMitigationEle = self.w2w.reports[fqdn].toElement()
                
                systemInfoEle = fqdnToSystemInfo[fqdn]
                hpaEle = self.hpa.reports[fqdn]
                hpaScore = hpaEle.find("score")
                hpaPenalties = hpaScore.findall("penalty")
    
                hostMitigationEle.append(systemInfoEle)
                hostMitigationScore = hostMitigationEle.find("score")
                hostMitigationScore.extend(hpaPenalties)
                
                
                
                
                
                
                hostMitigationScore.attrib["cumulativeScore"] = "XXX"
    
                outPath = os.path.join(self.outputDir, "LL_Pth_%s.xml" % fqdn)
                with open(outPath, 'wb') as f:
                    reparsed = minidom.parseString(ET.tostring(hostMitigationEle))
                    f.write(reparsed.toprettyxml(indent="\t"))
                
                
            except Exception as e:
                traceback.print_exc()
            
            
   
        
    
            
def main(inputDir, outputDir):
    try:
        analyzer = LL_PthAnalyzer(inputDir, outputDir)
        analyzer.process()
    except Exception:
        traceback.print_exc()
        return -1



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    
    parser.add_argument("-i", dest="inputDir", action="store", type=str, required=True)
    parser.add_argument("-o", dest="outputDir", action="store", type=str, required=True)
    
    args = parser.parse_args()
    
    main(args.inputDir, args.outputDir)