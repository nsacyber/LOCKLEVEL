import xml.etree.ElementTree as ET
import remediation

class InvalidPenaltyValueError(Exception):
    def __init__(self, msg):
        self.msg = msg
        
        
class InvalidW2WPenaltyReasonError(Exception):
    def __init__(self, msg):
        self.msg = msg
        
class Penalty(object):
    def __init__(self, name, value, reason, remediation, penaltyId):
        self.name = name
        
        try:
            self.value = int(value)
            if not Penalty.isValidPenaltyValue(value):
                raise InvalidPenaltyValueError("%d is not a valid penalty value (0 > x <= 100)" % value) 
            
        except ValueError:
            raise InvalidPenaltyValueError("%s is not a valid penalty value" % value)
        
        self.reasons = set()
        self.addReason(reason)
        
        self.remediation = remediation
        self.penaltyId = penaltyId
        
    
    def addReason(self, reason):
        self.reasons.add(reason)
    
    
    @staticmethod
    def isValidPenaltyValue(value):
        return value > 0 and value <= 100
        
            
    
    def getValue(self):
        return self.value
        
        
    def toElement(self, parent=None):
        top = None
        if parent is None:
            top = ET.Element("penalty", attrib={"id":self.penaltyId, "name":self.name, "value":str(self.value)})
        else:
            top = ET.SubElement(parent, "penalty", attrib={"id":self.penaltyId, "name":self.name, "value":str(self.value)})
        
        
        for reason in self.reasons:
            reasonElement = ET.SubElement(top, "reason")
            reasonElement.text = reason
            
            
        
        self.remediation.toElement(parent=top)
       
        return top
        


class W2W_CommunicationPenalty(Penalty):
    def __init__(self, src, dst, port):
        super(W2W_CommunicationPenalty, self).__init__("Workstation to workstation communication allowed",
                                                       10,
                                                       (src, dst, port),
                                                       remediation.Remediation("BLOCK_W2W_TRAFFIC", "Create firewall rule to block workstation to workstation traffic on port %d" % port),
                                                       "BLOCK_W2W_TRAFFIC")
        self.src = src
        self.dst = dst
        self.port = port
        
    def addReason(self, reason):
        if not isinstance(reason, tuple) or len(reason) != 3:
            raise InvalidW2WPenaltyReasonError("%s is not a valid W2W reason")
        super(W2W_CommunicationPenalty, self).addReason(reason)
    
                                                       
    def toElement(self, parent=None):
        top = None

        if parent is None:
            top = ET.Element("penalty", attrib={"id":self.penaltyId, "name":self.name, "value":str(self.value), "category":"Pth_w2wc"})
        else:
            top = ET.SubElement(parent, "penalty", attrib={"id":self.penaltyId, "name":self.name, "value":str(self.value), "category":"Pth_w2wc"})
            
        
        for src, dst, port in self.reasons:
            reasonElement = ET.SubElement(top, "reason")
            reasonElement.text = "%s can talk to %s on port %d" % (src, dst, port)
            
            #"%s can talk to %s on port %d" % (src, dst, port)
        
        self.remediation.toElement(parent=top)
       
        return top
        
