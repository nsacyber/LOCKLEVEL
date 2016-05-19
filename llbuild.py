import argparse
import os
import sys
import subprocess
import pdb
import shutil
import datetime
import logging
import zipfile
import threading

CMAKE = "cmake.exe"
MSBUILD = "msbuild.exe"


EXIT_SUCCESS = 0
EXIT_FAILURE = 1


LOG_FILE = 'build_log.txt'
LOG_NAME = 'build_logger'


def setup_logging(logpath, logname, append=False):
    """
    Initializes logging.
    """

    global log

    if not append and os.path.exists(logpath) and os.path.isfile(logpath):
        os.remove(logpath)

    log = logging.getLogger(logname)
    log.setLevel(logging.DEBUG)

    # Set up a file handler that will log errors
    fileHandler = logging.FileHandler(logpath)
    fileHandler.setLevel(logging.DEBUG)

    stdoutHandler = logging.StreamHandler(sys.stdout)
    stdoutHandler.setLevel(logging.DEBUG)
	
    stderrHandler = logging.StreamHandler(sys.stderr)
    stderrHandler.setLevel(logging.ERROR)

    fileFormatter = logging.Formatter('%(asctime)s %(levelname)s - %(message)s')
    consoleFormatter = logging.Formatter('%(levelname)s %(message)s')
	
    fileHandler.setFormatter(fileFormatter)
    stdoutHandler.setFormatter(consoleFormatter)
    stderrHandler.setFormatter(consoleFormatter)

    log.addHandler(fileHandler)
    log.addHandler(stdoutHandler)
    log.addHandler(stderrHandler)


def cleanup_logging(logpath, logname, force=False):
    """
    Perform cleanup actions for logging.
    """
    global log
	
    for handler in logging.getLogger(logname).handlers:
        handler.close()
        log.removeHandler(handler)

    logging.shutdown()
    del log

    if os.stat(logpath).st_size == 0 or force:
        os.remove(logpath)


def enum(**enums):
    return type('Enum', (), enums)

plugins = enum(AE=1, AV=2, AW=3, HIPS=4, OS=5, OSPH=6, PTH=7)

 
managedPlugins = set([plugins.AW, plugins.HIPS, plugins.OS, plugins.OSPH])
unmanagedPlugins = set([plugins.AE, plugins.AV, plugins.PTH])

llPlugins = managedPlugins.union(unmanagedPlugins)

pluginRootNames = {
               plugins.AE:"LL_AE",
               plugins.AV:"LL_AV",
               plugins.AW:"LL_AW",
               plugins.HIPS:"LL_HIPS",
               plugins.OS:"LL_OS",
               plugins.OSPH:"LL_OSPH",
               plugins.PTH:"LL_Pth_And_Credentials"
               }

pluginNames = {
             plugins.AE:"LL_AE",
             plugins.AV:"LL_AV",
             plugins.AW:"LL_AW",
             plugins.HIPS:"LL_HIPS",
             plugins.OS:"LL_OS",
             plugins.OSPH:"LL_OSPH",
             plugins.PTH:"LL_PtH"
             }

managedSurveyComponentsNames = {
                  plugins.AW: set([
                                   os.path.join("Survey", "LL_AW_Survey.ps1")]),
                  plugins.HIPS: set([
                                     os.path.join("Survey", "LL_HIPS_Survey.ps1")]),
                  plugins.OS: set([None]),
                  plugins.OSPH: set([os.path.join("Survey", "LL_OSPH_Survey.ps1")]),
                  }

pluginPayloadRequiredFiles = {
                      plugins.AE:set([
                                      "AntiExploitation.exe",
                                      "GetSystemInfo.exe",
                                      "ll_ae.bat"]),
                              
                      plugins.AV:set([
                                      "GetAVStatus.exe",
                                      "GetSystemInfo.exe",
                                      "ll_av.bat"]),
                              
                      plugins.AW:set([
                                      "GetSystemInfo.exe",
                                      "ll_aw.bat",
                                      "LL_AW_Survey.ps1"]),
                              
                      plugins.HIPS:set([
                                        "GetSystemInfo.exe",
                                        "ll_hips.bat",
                                        "LL_HIPS_Survey.ps1"]),
                              
                      plugins.OS:set([
                                      "GetSystemInfo.exe",
                                      "Get-SystemInfo.ps1",
                                      "ll_os.bat"]),
                              
                      
                      plugins.OSPH:set([
                                        "GetSystemInfo.exe",
                                        "ll_osph.bat",
                                        "LL_OSPH_Survey.ps1"]),
                              
                                        
                      plugins.PTH:set([
                                       "GetDomainRole.exe",
                                       "GetSystemInfo.exe",
                                       "HighPrivilegeAccountAuditing.exe",
                                       "NetworkMapperMT_driver.exe",
                                       "ll_pth.bat"])
                              
                      }

pluginAnalyzerDir = {
                     plugins.AE:"Analyzer",
                     plugins.AV:"Analyzer",
                     plugins.AW:"analyzer",
                     plugins.HIPS:"Analyzer",
                     plugins.OS:"Analyzer",
                     plugins.OSPH:"Analyzer",
                     plugins.PTH:"Analyzer"
                     }

pluginAnalyzerComponents = {
                            plugins.AE:set([
                                            "LL_AE.py",
                                            "penalties.xml"]),
                            plugins.AV:set([
                                            "AVFileReputationAnalyzer.py",
                                            os.path.join("penalties.xml")]),
                              
                            plugins.AW:set(["LL_AW_Analyzer.ps1",
                                            "penalties.xml"]),
                              
                            plugins.HIPS:set(["LL_HIPS_Analyzer.ps1",
                                              "penalties.xml"]),
                              
                            plugins.OS:set(["LL_OS_Analyzer.ps1",
                                            "penalties.xml"]),
                              
                            plugins.OSPH:set(["LL_OSPH_Analyzer.ps1",
                                              "penalties.xml"]),
                            
                            plugins.PTH:set([
                                             os.path.join("LL_PtH_analyzer",
                                                          "src",
                                                          "ll_pth_analyzer",
                                                          "LL_PthAnalyzer.py"),
                                             os.path.join("LL_PtH_analyzer",
                                                          "src",
                                                          "ll_pth_analyzer",
                                                          "llExtract.py"),
                                             os.path.join("LL_PtH_analyzer",
                                                          "src",
                                                          "ll_pth_analyzer",
                                                          "7z.dll"),
                                             os.path.join("LL_PtH_analyzer",
                                                          "src",
                                                          "ll_pth_analyzer",
                                                          "7z.exe"),
                                             os.path.join("LL_PtH_analyzer",
                                                          "src",
                                                          "ll_pth_analyzer",
                                                          "7-zip.dll"),
                                             os.path.join("privAnalyzer",
                                                          "src",
                                                          "privAnalyzer",
                                                          "privAnalyzer.py"),
                                             os.path.join("w2wAnalyzer",
                                                          "src",
                                                          "w2wAnalyzer",
                                                          "mitigation.py"),
                                             os.path.join("w2wAnalyzer",
                                                          "src",
                                                          "w2wAnalyzer",
                                                          "path.py"),
                                             os.path.join("w2wAnalyzer",
                                                          "src",
                                                          "w2wAnalyzer",
                                                          "penalty.py"),
                                             os.path.join("w2wAnalyzer",
                                                          "src",
                                                          "w2wAnalyzer",
                                                          "remediation.py"),
                                             os.path.join("w2wAnalyzer",
                                                          "src",
                                                          "w2wAnalyzer",
                                                          "systemInfo.py"),
                                             os.path.join("w2wAnalyzer",
                                                          "src",
                                                          "w2wAnalyzer",
                                                          "w2wAnalyzer.py"),
                                             os.path.join("w2wPostProcessing",
                                                          "src",
                                                          "w2wPostProcessing",
                                                          "w2wPostProcessing.py")
                                             ])
                            
                            }


bsPluginLLRootRelativeDirs = {
                            plugins.AE:os.path.join("LL_AE", "LL_AE"),
                            plugins.AV:os.path.join("LL_AV", "LL_AV"),
                            plugins.AW:"LL_AW",
                            }

assert managedPlugins.intersection(unmanagedPlugins) == set()


FINAL_BUILD_ANALYZERS_DIR = "Analyzers"
FINAL_BUILD_LOGS_DIR = "Logs"
FINAL_BUILD_OUTPUT_DIR = "Output"
FINAL_BUILD_PLUGINS_DIR = "Plugins"


def which(pathToExe):
    """
    @summary: Function to do a linux-like 'which' command.  
    """
    def isExe(filepath):
        #allows to look for both calc and calc.exe
        return (os.path.isfile(filepath) and os.path.basename(filepath).endswith(".exe")) or \
            (os.path.isfile(filepath + ".exe"))
    
    dirpath, _ = os.path.split(pathToExe)
    if dirpath:
        #this is an absolute path
        return isExe(pathToExe)
    else:
        #this is a relative path
        
        #check current working directory
        if isExe(pathToExe):
            return pathToExe


        #iterate over all items in the path        
        #check path
        for path in os.environ["PATH"].split(os.pathsep):
            newExePath = os.path.join(path, pathToExe)
            if isExe(newExePath):
                return newExePath
            
            
    return None

def zip(src, dst):
    z = zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED)
    for directory, subdirectory, files in os.walk(src):
        for filename in files:
            absname = os.path.abspath(os.path.join(directory, filename))
            archive = absname[len(src)+1:]
            z.write(absname, archive)
    z.close()
   
   
def unzip(src, dst):
    z = zipfile.ZipFile(src)
    z.extractall(dst)


def getKPluginPath(llRoot, plugin):
    global pluginRootNames
    global pluginNames
    return os.path.join(
                        llRoot,
                        os.path.dirname(getPluginSolutionPath(llRoot, plugin)),
                        "PluginTester",
                        "plugins",
                        "%s.kplugin" % pluginNames[plugin])

def getPluginBatFile(llRoot, plugin):
    global pluginRootNames
    global pluginNames
    return os.path.join(
                        llRoot, 
                        pluginRootNames[plugin], 
                        pluginNames[plugin],
                        pluginNames[plugin],  
                        "%s.bat" % pluginNames[plugin] )



def getPluginSolutionPath(llRoot, plugin):
    global pluginRootNames
    global pluginNames
    return os.path.join(
                        llRoot, 
                        pluginRootNames[plugin], 
                        pluginNames[plugin],
                        "%s.sln" % pluginNames[plugin])
    
    
def getAnalyzerPath(llRoot, plugin):
    global pluginRootNames
    global pluginNames
    global pluginAnalyzerDir
    return os.path.join(
                        llRoot, 
                        pluginRootNames[plugin], 
                        pluginAnalyzerDir[plugin])
    
    

def _invokeCmd(cmd, stdout, stderr):

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdoutData, stderrData = proc.communicate()

    if stdoutData:
        log.info('\r\n' + stdoutData)

    if stderrData:
        log.error('\r\n' + stderrData)

    proc.wait()

    if proc.returncode != 0:
        log.error("cmd: %s returned error status: %d" % (' '.join(cmd), proc.returncode))

    return proc.returncode == 0


def _buildRootSolutionFile(buildDir, inputMakefilePath, vsVersion, isx64=False):
    vsName = ''
    runtimeName = ''

    if vsVersion.upper() == 'VS2015':
        vsName = 'Visual Studio 14 2015'
        runtimeName = 'v140_xp'
    elif vsVersion.upper() == 'VS2013':
        vsName = 'Visual Studio 12 2013'
        runtimeName = 'v120_xp'
    else:
        log.error('Unsupported Visual Studio version: %s' % vsVersion)
        return False
		
    generatorName = vsName + ' Win64' if isx64 else vsName
	
    cmd = [CMAKE, 
           "-G",
           generatorName,
           "-T",
           runtimeName,
           '-H%s' % os.path.dirname(inputMakefilePath),
           '-B%s' % buildDir]
	
    return _invokeCmd(cmd, sys.stdout, sys.stderr)
        
def _compileLLCode(buildRootPath, buildType):
    cmd = [CMAKE, 
           "--build",
           buildRootPath,
           "--config",
           buildType,
           "--clean-first"]

    return _invokeCmd(cmd, sys.stdout, sys.stderr)    
    
    
def copyManagedSurveyCodeToPayload(llRoot):
    global managedPlugins
    global collectorNames
    global plugins
    success = True
    
    for managedPlugin in managedPlugins:
        if managedPlugin == plugins.OS:
            shutil.copy(os.path.join(llRoot, "GetSystemInfo", "GetSystemInfo", "Get-SystemInfo.ps1"),
                   getPluginPayloadDirectory(llRoot, managedPlugin))
            
        
        for collectorComponent in managedSurveyComponentsNames[managedPlugin]:
            if collectorComponent is None:
                continue
            src = getComponentPath(llRoot, managedPlugin, collectorComponent)
            dst = getPluginPayloadDirectory(llRoot, managedPlugin)
            
            if not copyComponent(src, dst):
                success = False
                
    return success


def copyComponent(src, dst):
    log.info("Copying:\n\t src: %s\n\tdst: %s" % (src, dst))
    try:
        shutil.copy(src, dst)
        return True
    except shutil.Error:
        #src/dst are the same file
        return True
    except IOError:
        if not os.path.exists(src):
            log.error("Source file does not exist %s" % src)
        
        if not os.path.exists(dst):
            log.error("Destination path does not exist %s" % dst)

        return False
        

def copyPluginBatchFiles(llRoot):
    global llPlugins
    global pluginNames
    success = True
    
    for plugin in llPlugins:
        batchFilePath = getPluginBatFile(llRoot, plugin)
        payloadPath = getPluginPayloadDirectory(llRoot, plugin)
        
        if not copyComponent(batchFilePath, payloadPath):
            success = False

        
    return success                             
        

def buildLL32Code(buildRootPath, inputMakefilePath, buildType, vsVersion):
    if not _buildRootSolutionFile(buildRootPath, inputMakefilePath, vsVersion, isx64=False):
        return False
    
    if not _compileLLCode(buildRootPath, buildType):
        return False
    
    
    return True


def buildLL64Code(buildRootPath, inputMakefilePath, buildType, vsVersion):
    if not _buildRootSolutionFile(buildRootPath, inputMakefilePath, vsVersion, isx64=True):
        return False
    
    if not _compileLLCode(buildRootPath, buildType):
        return False
    
    
    return True


def verifyAllRequiredFilesPresent(llRoot):
    global llPlugins
    global pluginPayloadRequiredFiles
    success = True
    for plugin in llPlugins:
        for component in pluginPayloadRequiredFiles[plugin]:
            requiredComponentPath = os.path.join(
                                    getPluginPayloadDirectory(llRoot, plugin),
                                    component)
            if not os.path.exists(requiredComponentPath):
                log.error("Could not find component %s." % requiredComponentPath)
                success = False
                
    return success


def _startFreshAnalyzers(analyzersRoot):
    log.info("Removing old analyzers: %s" % analyzersRoot)
    
    if os.path.exists(analyzersRoot):
        shutil.rmtree(analyzersRoot)
    
    os.makedirs(analyzersRoot)
    os.makedirs(os.path.join(analyzersRoot, "Code"))
    os.makedirs(os.path.join(analyzersRoot, "Output"))
    
    
def _startFreshDeployBatchFiles(deployBatchFilesRoot):
    log.info("Removing old DeployBatchFiles: %s" % deployBatchFilesRoot)
	
    if os.path.exists(deployBatchFilesRoot):
        shutil.rmtree(deployBatchFilesRoot)
    
    
def _startFreshLogs(logsRoot):
    log.info("Removing old logs: %s" % logsRoot)

    if os.path.exists(logsRoot):
        shutil.rmtree(logsRoot)
        
    os.makedirs(logsRoot)
    
    
def _startFreshOutput(outputRoot):
    log.info("Removing old Output: %s" % outputRoot)

    if os.path.exists(outputRoot):
        shutil.rmtree(outputRoot)
        
    os.makedirs(outputRoot)
    
    
    
def _startFreshPlugins(pluginsRoot):
    log.info("Removing old Plugins: %s" % pluginsRoot)
    
    if os.path.exists(pluginsRoot):
        shutil.rmtree(pluginsRoot)
        
    os.makedirs(pluginsRoot)


def startFresh(guiRoot):
    _startFreshAnalyzers(os.path.join(guiRoot, "Analyzers"))
    _startFreshDeployBatchFiles(os.path.join(guiRoot, "DeployBatchFiles"))
    _startFreshLogs(os.path.join(guiRoot, "Logs"))
    _startFreshOutput(os.path.join(guiRoot, "Output"))
    _startFreshPlugins(os.path.join(guiRoot, "Plugins"))
    
    
def copyAnalyzerToFinalBuild(srcPluginAnalyzerRoot, dstPluginAnalyzerRoot, plugin ):
    for component in pluginAnalyzerComponents[plugin]:
        curAnalyzerPath =  os.path.join(srcPluginAnalyzerRoot, component)
        if not os.path.exists(dstPluginAnalyzerRoot):
            os.makedirs(dstPluginAnalyzerRoot)
        shutil.copy(curAnalyzerPath, dstPluginAnalyzerRoot)
    
def copyAnalyzersToFinalBuild(llRoot, analyzersRoot):
    global llPlugins
    for plugin in llPlugins:
        copyAnalyzerToFinalBuild(
                                 getAnalyzerPath(llRoot, plugin),
                                 os.path.join(analyzersRoot, pluginNames[plugin]),
                                 plugin)
            
def copyPluginToFinalBuild(srcPluginRoot, dstPluginRoot, plugin ):
    shutil.copy(srcPluginRoot, dstPluginRoot)
            
def copyPluginsToFinalBuild(llRoot, pluginsRoot):
    global llPlugins
    for plugin in llPlugins:
        copyPluginToFinalBuild(getKPluginPath(llRoot, plugin), 
                               pluginsRoot,
                               plugin)
    

def copyLLComponentsToFinalBuild(llRoot, buildRoot):
    global FINAL_BUILD_ANALYZERS_DIR
    copyAnalyzersToFinalBuild(llRoot,
                              os.path.join(buildRoot, FINAL_BUILD_ANALYZERS_DIR, "Code"))
    
    copyPluginsToFinalBuild(llRoot,
                            os.path.join(buildRoot, FINAL_BUILD_PLUGINS_DIR))
    
    
def copyScoremaster(llRoot, buildRoot):
    scoremasterRoot = os.path.join(llRoot, "scoremaster")
    scoremasterOutRoot = os.path.join(buildRoot, "scoremaster")
    scoremasterOutCodePath = os.path.join(scoremasterOutRoot, "code")
    
    os.makedirs(scoremasterOutCodePath)
    shutil.copy(os.path.join(scoremasterRoot, 'scoremaster.py'), scoremasterOutCodePath)
    os.makedirs(os.path.join(scoremasterOutRoot, "output"))
    
    
def copyPresentation(llRoot, thisBuildRoot):
    presentationRoot = os.path.join(llRoot, "presentation")
    presentationOutRoot = os.path.join(thisBuildRoot, "presentation")
    
    shutil.copytree(presentationRoot, os.path.join(presentationOutRoot, "Code"))
    os.makedirs(os.path.join(presentationOutRoot, "Output"))
	
def copyDocumentation(llRoot, thisBuildRoot):
    documentationRoot = os.path.join(llRoot, "documentation")
    documentationOutRoot = os.path.join(thisBuildRoot, "documentation")
	
    shutil.copytree(documentationRoot, documentationOutRoot)

    shutil.copyfile(os.path.join(llRoot, 'LICENSE.md'), os.path.join(documentationOutRoot, 'LICENSE.txt'))
    shutil.copyfile(os.path.join(llRoot, 'DISCLAIMER.md'), os.path.join(documentationOutRoot, 'DISCLAIMER.txt'))	

def buildLocklevel(llRoot, guiPath, outRoot):   
    #create directory structure    
    rightNow = datetime.datetime.now()
    timeFormat = rightNow.strftime("%Y%m%d%H%M%S")
    thisBuildRoot = os.path.join(
                                 outRoot, 
                                 timeFormat, 
                                 "LOCKLEVEL")
   
    #copy over llgui
    shutil.copytree(guiPath, thisBuildRoot)
    
    #remove unnecessary stuff
    startFresh(thisBuildRoot)
    
    copyLLComponentsToFinalBuild(llRoot, thisBuildRoot)
    
    copyScoremaster(llRoot, thisBuildRoot)
    
    copyPresentation(llRoot, thisBuildRoot)

    copyDocumentation(llRoot, thisBuildRoot)

    zipPath = os.path.join(outRoot, timeFormat, "LOCKLEVEL_%s.zip" % timeFormat)

    zip(thisBuildRoot, zipPath)
	
    log.info("LOCKLEVEL folder:  %s" % thisBuildRoot)
    log.info("LOCKLEVEL zip file: %s " % zipPath)

    return True


def _buildPlugin(slnPath, buildType):
    cmd = ["msbuild.exe", 
            slnPath,
            '/p:Configuration=%s' % buildType]
    return _invokeCmd(cmd, sys.stdout, sys.stderr) 


def buildPlugins(llRoot, buildType):
    global llPlugins
    success = True
    for plugin in llPlugins:
        pluginSolutionPath = getPluginSolutionPath(llRoot, plugin)
        if not os.path.exists(pluginSolutionPath):
            success = False
            log.error("Could not find .sln file %s" % pluginSolutionPath)
        else:
            if not _buildPlugin(pluginSolutionPath, buildType):
                success = False
                log.error("Could not build %s" % pluginSolutionPath)
        
        
    return success


def build(llRoot, buildDir, inputMakefilePath, guiPath, outRoot, buildType, vsVersion):

    buildDir32 = os.path.join(buildDir, os.path.basename(buildDir)+"32")
    buildDir64 = os.path.join(buildDir, os.path.basename(buildDir)+"64")
    
    os.makedirs(buildDir32)
    os.makedirs(buildDir64)
    
    if not buildLL32Code(buildDir32, inputMakefilePath, buildType, vsVersion):
        return False
    
    if not buildLL64Code(buildDir64, inputMakefilePath, buildType, vsVersion):
        return False
    
    
    if not copyManagedSurveyCodeToPayload(llRoot):
        return False
     
    
    if not copyPluginBatchFiles(llRoot):
        return False
       
    if not verifyAllRequiredFilesPresent(llRoot):
        return False
    
    if not buildPlugins(llRoot, buildType):
        return False
       
    if not buildLocklevel(llRoot, guiPath, outRoot):
        return False
    
    return True


def getPluginProjectDirectory(llRoot, plugin):
    return os.path.join(
                        llRoot,
                        pluginRootNames[plugin],
                        pluginNames[plugin],
                        pluginNames[plugin])

def getPluginPayloadDirectory(llRoot, plugin):
    return os.path.join(
                        getPluginProjectDirectory(llRoot, plugin),
                        "payload")
    
def getComponentPath(llRoot, plugin, collectorComponent):
    return os.path.join(
                        llRoot,
                        pluginRootNames[plugin],
                        collectorComponent)

def verifyPreconditions(llRoot, inputMakefilePath, guiPath):
    if which(CMAKE) is None:
        log.error("Unable to find %s in current working directory or system path" % CMAKE)
        return False

    if which(MSBUILD) is None:
        log.error("Unable to find %s in current working directory or system path" % MSBUILD)
        return False
    
    if not os.path.exists(llRoot):
        log.error("LOCKLEVEL root %s does not exist" % llRoot)
        return False

    if not os.path.exists(inputMakefilePath):
        log.error("Make file %s does not exist" % inputMakefilePath)
        return False

    if not os.path.exists(guiPath):
        log.error("GUI zip file %s does not exist" % guiPath)
        return False

    return True


def main(llRoot, buildDir, inputMakefilePath, guiPath, outRoot, buildType, vsVersion):
    if not verifyPreconditions(llRoot, inputMakefilePath, guiPath):
        log.error("***FAILURE***")
        return EXIT_FAILURE

    if os.path.exists(buildDir) and os.path.isdir(buildDir):
        shutil.rmtree(buildDir, ignore_errors=True)

    os.makedirs(buildDir)
 
    unarchivedGuiPath = os.path.join(buildDir, "locklevelGui") 
    unzip(guiPath, unarchivedGuiPath)
 
    log.info("Visual Studio version: %s" % vsVersion)
    log.info("Build type: %s" % buildType)
 
    if not build(llRoot, buildDir, inputMakefilePath, unarchivedGuiPath, outRoot, buildType, vsVersion):
        log.error("***FAILURE***")
        return EXIT_FAILURE

    log.info("***SUCCESS***")
    
    return EXIT_SUCCESS
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", dest="buildDir", action="store", type=str, default="_build")
    parser.add_argument("-g", dest="guiPath", action="store", type=str, default="locklevelGUI.zip")
    parser.add_argument("-i", dest="inputMakefile", action="store", type=str, default="CMakeLists.txt")
    parser.add_argument("-l", dest="llRoot", action="store", type=str, default = ".")
    parser.add_argument("-o", dest="outRoot", action="store", type=str, default="_build")
    parser.add_argument("-r", dest="releaseType", action="store", type=str, default="Release", choices=['Debug','Release'])
    parser.add_argument("-v", dest="vsVersion", action="store", type=str, default="VS2015", choices=['VS2013','VS2015'])

    log_path = os.path.abspath(LOG_FILE)

    setup_logging(log_path, LOG_NAME)
	
    args = parser.parse_args()
    
    main(
         os.path.abspath(args.llRoot), 
         os.path.abspath(args.buildDir), 
         os.path.abspath(args.inputMakefile), 
         os.path.abspath(args.guiPath), 
         os.path.abspath(args.outRoot),
         args.releaseType,
         args.vsVersion
		 )

    cleanup_logging(log_path, LOG_NAME)

    if os.path.exists(log_path) and os.path.exists(os.path.abspath(args.buildDir)):
        shutil.move(log_path, os.path.join(os.path.abspath(args.buildDir), LOG_FILE))
