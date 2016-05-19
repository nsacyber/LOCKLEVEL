import pdb

class InvalidPortValueError(Exception):
    pass

class Path(object):
    def __init__(self,src, dst, port):
        self.src = src
        self.dst = dst
        try:
            self.port = int(port)
        except ValueError:
            raise InvalidPortValueError()
        
    @staticmethod 
    def _isValidPathTuple(t):
        return isinstance(t, tuple) and len(t) == 3 
        
    @staticmethod
    def _isValidPathString(pathAsString):
        return isinstance(pathAsString, str) and pathAsString.count(',') == 2
            
    
    @staticmethod
    def create(pathAsStringOrTuple):
        if Path._isValidPathTuple(pathAsStringOrTuple):
            return Path(*pathAsStringOrTuple)
            
        elif Path._isValidPathString(pathAsStringOrTuple):
            src, dst, port = pathAsStringOrTuple.split(',')
            return Path(src, dst, port)
        
        else:
            return None
                
        
    
    
    def __str__(self):
        return "path=(%s, %s, %d)" % (self.src, self.dst, self.port)
        