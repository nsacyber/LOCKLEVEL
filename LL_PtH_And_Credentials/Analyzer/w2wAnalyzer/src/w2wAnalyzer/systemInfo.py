import xml.etree.ElementTree as ET

class InvalidSystemInfoXmlError(Exception):
    pass

class SystemInfo(object):
    def __init__(self, xmlAsString):
        root = ET.fromstring(xmlAsString)
            
        hostEle = root.find("hostName")
        if hostEle is None:
            raise InvalidSystemInfoXmlError
        
        self.hostname = hostEle.text
        
        domainEle = root.find("domainName")
        if domainEle is None:
            raise InvalidSystemInfoXmlError
        
        
        self.domainName = domainEle.text
        
        
    def getFqdn(self):
        return "%s.%s" % (self.hostname, self.domainName)
    
    @staticmethod
    def fromFile(filename):
        with open(filename, 'rb') as f:
            return SystemInfo(f.read())
    
        
