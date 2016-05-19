import pdb
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom

import penalty

class Mitigation(object):
    def __init__(self, name, hostname):
        self.name = name
        self.hostname = hostname
        self.penalties = []
        
        
    def addPenalty(self, newPenalty):
        #look to see if there are any penalties of this type of mitigation
        if isinstance(newPenalty, penalty.W2W_CommunicationPenalty):
            existingPenalty = filter(lambda x: x.port == newPenalty.port and x.dst == newPenalty.dst, self.penalties) 
            if existingPenalty:
                #penalty exists...add another reason
                existingPenalty[0].addReason((newPenalty.src, newPenalty.dst, newPenalty.port))
                
            else:
                #penalty doesn't exist add it
                self.penalties.append(newPenalty)
        else:
            #penalty doesn't exist add it
            self.penalties.append(newPenalty)
        
    
    def getScore(self):
        score = 9.0
        for penalty in self.penalties:
            if score <= 0.0:
                #more penalties don't matter anymore
                score = 0.0
                break
            
            score *=  ((100 - penalty.getValue()) / 100.0)
     
        
        #round to 1 decimal place
        return float("{0:.1f}".format(round(score+1, 1))) 
    
    
    def toElement(self, parent = None):
        element = None
        if parent is None:
            element = ET.Element("mitigation", attrib={"name":self.name })

        else:
            element = ET.SubElement(parent, "mitigation", attrib={"name":self.name})
            
            
        scoreElement = ET.SubElement(element, "score", attrib={"cumulativeScore":str(self.getScore())})
        for penalty in self.penalties:
            penalty.toElement(parent=scoreElement)
        
        return element
    
    
    
    def write(self, f):
        rawXmlAsString = ET.tostring(self.toElement())
        reparsed = minidom.parseString(rawXmlAsString)
        f.write(reparsed.toprettyxml(indent="\t"))
    
    
        