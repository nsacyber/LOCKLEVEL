"""
@summary: An extraction utility for lock level results.  Given a .zip file as an
input parameter llExtract.py unzips the archive and outputs all files that are
prefixed by a case insensitive comparison with the string "ll".

@precondition: Assumes that 7z.exe is somewhere in %PATH%  

"""

import argparse
import subprocess
import os.path
import pdb

USAGE = "python llExtract.py <filename.zip>"

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
SEVENZIP_EXE = "7z.exe"

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
    

class ArgumentParserError(Exception):
    pass

class ArgumentParserWithCustomErrorHandling(argparse.ArgumentParser):
    def error(self, message):
        raise ArgumentParserError(message)
    
    
class LLExtracter(object):
    def __init__(self, filename):
        self.filename = os.path.abspath(filename)
    
    @staticmethod
    def getOutputDirectoryPath(filepath):
        baseFilenameNoExt, _ = os.path.splitext(os.path.basename(filepath))
        return os.path.abspath(os.path.join(os.path.dirname(filepath), baseFilenameNoExt))    
    
    def extract(self):
        """
        @summary: Extract all of the files in <self.filename>
        """
        global SEVENZIP_EXE
        
        assert self.filename is not None
        
        #run the unzip command
        with open(os.devnull) as devnull:
            #run 7zip
            #options: 
            #e=extract
            #-y= say yes to everything (overwrites)
            #-o<directory>= the output directory
            cmd = [SEVENZIP_EXE, 
                   "e", 
                   "-y", 
                   "-o%s" % LLExtracter.getOutputDirectoryPath(self.filename), 
                   self.filename]
            
            #redirect stdout to devnull and stderr to stdout.
            #so we can get error messages if they occur
            p = subprocess.Popen(cmd, stdout=devnull, stderr=subprocess.STDOUT)
            p.wait()
        
        #check error status
        if p.returncode != 0:
            #an error happened
            print "Error extracting archive %s" % self.filename
            return False
        
        #after unzip command there should be a folder with the same name as filename 
        #minus the .zip extension
        expectedDir, _ = os.path.splitext(self.filename)
        
        #post condition...
        #a directory exists with the name of the filename minus the .zip extension
        assert os.path.exists(os.path.abspath(expectedDir))
        assert os.path.isdir(os.path.abspath(expectedDir))
           
        
        return True
    
    def getResults(self, outdirPath):
        results = []
        for root, _, names in os.walk(outdirPath):
            results.extend([os.path.abspath(os.path.join(root, filename)) for filename in names if filename.lower().startswith("ll")])
        
        return results
    
    
    def run(self):
        #loooks for 7zip in the path
        if which(SEVENZIP_EXE) is None:
            print "Can't find %s in PATH" % SEVENZIP_EXE
            return
        
        
        if not self.extract():
            print "Error extracting %s" % self.filename
        else:
            results = self.getResults(LLExtracter.getOutputDirectoryPath(self.filename))
            
            print ' '.join(['"%s"' % filename for filename in results])
    
def main(archivePath):
    extracter = LLExtracter(archivePath)
    extracter.run()
    



if __name__ == "__main__":
    parser = ArgumentParserWithCustomErrorHandling(description="Extract plugin results archive")
    parser.add_argument('archive', type=str)
    args = None
    try:
        args = parser.parse_args()
    except ArgumentParserError, exc:
        print USAGE
        exit(EXIT_FAILURE)
        
    main(args.archive)
