import xml.etree.ElementTree as ET

class Remediation(object):
    def __init__(self, remediationId, text):
        self.remediationId = remediationId
        self.text = text
        
    def getId(self):
        return self.remediationId
        
    def getText(self):
        return self.text
        
    def toElement(self, parent=None):
        element = None
        if parent is None:
            element =  ET.Element("remediation", attrib={"id":self.remediationId})
        else:
            element =  ET.SubElement(parent, "remediation",  attrib={"id":self.remediationId})
        
        element.text = self.text
        return element
  
        