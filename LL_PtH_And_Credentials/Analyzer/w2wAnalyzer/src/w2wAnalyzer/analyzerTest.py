import unittest
import pdb
import xml.etree.ElementTree as ET

from path import Path, InvalidPortValueError
from penalty import Penalty, InvalidPenaltyValueError, W2W_CommunicationPenalty, InvalidW2WPenaltyReasonError
from remediation import Remediation
from mitigation import Mitigation
from systemInfo import SystemInfo, InvalidSystemInfoXmlError


class Test_PathCreationAsString(unittest.TestCase):
    def setUp(self):
        self.input = ["src.domain.com,target.domain.com,135\n",
                     "src.domain.com,target.domain.com,139\n",
                     "src.domain.com,target.domain.com,445\n"
                     ]
 
    def tearDown(self):
        pass
    
    def test_PathCreateReturnsRightType(self):
        pathAsString = self.input[0]
        openPath = Path.create(pathAsString)
        
        self.assertIsNotNone(openPath)
        self.assertIsInstance(openPath, Path)
        
    def test_PathCreateReturnsWithMembersOfCorrectType(self):
        pathAsString = self.input[0]
        openPath = Path.create(pathAsString)
        
        self.assertIsInstance(openPath.src, str)
        self.assertIsInstance(openPath.dst, str)
        self.assertIsInstance(openPath.port, int)
        
        
    def test_PathCreateWithEmptyStringReturnsNone(self):
        self.assertIsNone(Path.create(""))
        
    def test_PathCreateWithTabReturnsNone(self):
        self.assertIsNone(Path.create("\t"))
    
    def test_PathCreateWithNewlineReturnsNone(self):
        self.assertIsNone(Path.create("\t"))
        
        
    def test_PathCreateWithMalformedInputReturnsNone(self):
        self.assertIsNone(Path.create("asdf,asdf"))
        
        
class Test_PathCreationAsTuple(unittest.TestCase):
    def test_PathCreateAsTupleSucceeds(self):
        self.assertIsNotNone(Path.create(("asdf,asdf,10")))
        
    def test_PathCreateAsTupleFailsBadPort(self):
        with self.assertRaises(InvalidPortValueError):
            Path.create(("asdf,asdf,asdf"))
        
    def test_PathCreateAsTwoElementTupleReturnsNone(self):
        self.assertIsNone(Path.create(("asdf,asdf")))
            
        
        
class Test_PenaltyCreation(unittest.TestCase):
    def setUp(self):
        pass
        
    def tearDown(self):
        pass
    
    
    def test_PenaltyCreationReturnsPenaltyType(self):
        penalty = Penalty("name", 1, "reason", "remediation", "penaltyId")
        self.assertIsNotNone(penalty)
        self.assertIsInstance(penalty, Penalty)
        
    def test_PenaltyCreationWithInvalidNumericalValueThrowsError(self):
        with self.assertRaises(InvalidPenaltyValueError):
            Penalty(None, -1, None, None, None)
        
    def test_PenaltyValue100IsValid(self):
        self.assertTrue(Penalty.isValidPenaltyValue(100))
        
    def test_PenaltyInvalidValueGreaterThan100(self):
        self.assertFalse(Penalty.isValidPenaltyValue(100.01))
        
    def test_PenaltyInvalidValueEqualToZero(self):
        self.assertFalse(Penalty.isValidPenaltyValue(0))
        
    def test_PenaltyInvalidValueLTEZero(self):
        self.assertFalse(Penalty.isValidPenaltyValue(-1))
        
    def test_PenaltyWithNonIntegerParameter(self):
        with self.assertRaises(InvalidPenaltyValueError):
            Penalty("name", "value", "reason", "remediation", "penaltyId")
     
     
    def test_reasonIsOfTypeSet(self):
        penalty = Penalty("name", 1, "reason", "remediation", "penaltyId")
        self.assertIsInstance(penalty.reasons, set)    
        
    def test_penaltyHasOneReasonAfterCreation(self):
        penalty = Penalty("name", 1, "reason", "remediation", "penaltyId")
        self.assertEqual(len(penalty.reasons), 1)
        
    def test_penaltyHasTwoReasonsAfterOneIsAdded(self):
        penalty = Penalty("name", 1, "reason", "remediation", "penaltyId")
        penalty.addReason("reason2")
        self.assertEqual(len(penalty.reasons), 2)
        

class Test_PenaltyToElement(unittest.TestCase):
    def setUp(self):
        self.penaltyName = "name"
        self.value = 1
        self.reasons = "I have my reasons"
        self.penaltyId = "penaltyId"
        self.remediationText = "This is how you do better"
        self.remediation = Remediation(self.penaltyId, self.remediationText)
        
        
        self.penalty = Penalty(self.penaltyName, self.value, self.reasons, self.remediation, self.penaltyId)
    
    def tearDown(self):
        pass
    
    
    def test_PenaltyCreatesPenaltyTag(self):
        xml = self.penalty.toElement()
        
        
        self.assertEqual(xml.tag, "penalty")
        
    def test_PenaltyCreatesCorrectAttributesWithTag(self):
        element = self.penalty.toElement()
        
        
        self.assertEqual(element.attrib["name"], self.penaltyName)
        self.assertEqual(element.attrib["value"], str(self.value))
        self.assertEqual(element.attrib["id"], self.penaltyId)
        
        
    def test_PenaltyCreatesReasonChildElement(self):
        element = self.penalty.toElement()
        reasonChild = element.find("reason")
        
        self.assertIsNotNone(reasonChild)
        
        self.assertEqual(reasonChild.tag, "reason")
        self.assertEqual(reasonChild.text, self.reasons)
        
    def test_PenaltyCreatesRemediationChildElement(self):
        element = self.penalty.toElement()
        remediationChild = element.find("remediation")
        
        self.assertIsNotNone(remediationChild)
        
        self.assertEqual(remediationChild.tag, "remediation")
        self.assertEqual(remediationChild.text, self.remediation.getText())
        
        
    def test_PenaltyToElementAsAChild(self):
        parent = ET.Element("top")
        self.penalty.toElement(parent=parent)
        
        self.assertIsNotNone(parent.find("penalty"))
        
        
class Test_RemediationToElement(unittest.TestCase):
    def setUp(self):
        self.remediationId = "myId"
        self.remediationText = "this is the remediation"
        
    
    
    def tearDown(self):
        pass
    
    
    def test_RemediationCreatesRemediationTag(self):
        remediation = Remediation(self.remediationId, self.remediationText)
        remediationElement = remediation.toElement()
        
        self.assertIsNotNone(remediationElement)
        self.assertEqual(remediationElement.tag, "remediation")
        
        
    def test_RemediationCreatesIdAttribute(self):
        remediation = Remediation(self.remediationId, self.remediationText)
        remediationElement = remediation.toElement()
        
        self.assertIsNotNone(remediationElement)
        self.assertEqual(remediationElement.attrib["id"], self.remediationId)
    
    
    def test_RemediationCreatesElementText(self):
        remediation = Remediation(self.remediationId, self.remediationText)
        remediationElement = remediation.toElement()
        
        self.assertIsNotNone(remediationElement)
        self.assertEqual(remediationElement.text, self.remediationText)
        
        
class Test_RemediationToSubElement(unittest.TestCase):
    def setUp(self):
        self.penaltyName = "name"
        self.value = 1
        self.reasons = "I have my reasons"
        self.penaltyId = "penaltyId"
        self.remediationText = "This is how you do better"
        self.remediation = Remediation(self.penaltyId, self.remediationText)
        
        
        self.penalty = Penalty(self.penaltyName, self.value, self.reasons, self.remediation, self.penaltyId)
        
        
    def tearDown(self):
        pass
    
    
    def test_RemediationAsChildElementHasAParent(self):
        element = ET.Element("top")
        self.remediation.toElement(element)
        
        
        self.assertIsNotNone(element.find("remediation"))
        
        
class Test_MitigationCreate(unittest.TestCase):
    def setUp(self):
        self.mitigation = Mitigation("test", "host")
    
    
    def tearDown(self):
        pass
    
    
    def test_MitigationCreateIsNotNone(self):
        self.assertIsNotNone(self.mitigation)
        
    def test_MitigationStartsWithNoPenalties(self):
        self.assertEqual(len(self.mitigation.penalties), 0)
        
    def test_MitigationAddPenaltySizeIsNowOne(self):
        self.mitigation.addPenalty(Penalty("asdf", 1, "asdf", None, "asdf"))
        self.assertEqual(len(self.mitigation.penalties), 1)
        
        
    def test_scoreWithNoPenaltiesIsTen(self):
        self.assertEqual(self.mitigation.getScore(), 10.0)
        
        
    def test_scoreWithOneHundredPercentPenaltiesIsOne(self):
        self.mitigation.addPenalty(Penalty(None, 100, None, None, None))
        self.assertEqual(self.mitigation.getScore(), 1.0)
        
        
    def test_scoreShouldOnlyReturnOneDecimalPlace(self):
        self.mitigation.addPenalty(Penalty(None, 12, None, None, None))
        self.assertEqual(self.mitigation.getScore(), 8.9)
        
       
       
class Test_MitigationToElement(unittest.TestCase):
    def setUp(self):
        self.mitigationName = "test"
        self.hostname = "hostname"
        self.mitigation = Mitigation(self.mitigationName, self.hostname)
        self.mitigationElement = self.mitigation.toElement()
    
    def tearDown(self):
        pass
    
    def test_MitigationCreatesMitigationTag(self):
        self.assertIsNotNone(self.mitigationElement)
        self.assertEqual(self.mitigationElement.tag, "mitigation")
        
    def test_MitigationElementHasANameAttribute(self):
        self.assertEqual(self.mitigationElement.attrib["name"], self.mitigationName)
        
        
    def test_hasScoreTag(self):
        self.assertIsNotNone(self.mitigationElement.find("score"))
        
    def test_ScoreTagHasCumulativeScoreAttribute(self):
        scoreElement = self.mitigationElement.find("score")
        self.assertIsNotNone(scoreElement.attrib["cumulativeScore"])
        
        
    def test_NoPenaltiesHasZeroPenaltyElements(self):
        self.assertIsNone(self.mitigationElement.find("penalty"))
    
    def test_OnePenaltiesHasOnePenaltyElement(self):
        self.mitigation.addPenalty(Penalty("asdf", 1, "asdf", Remediation("myId", "do this"), "asdf"))
        self.assertEqual(len(self.mitigation.toElement().findall("./*/penalty")), 1)
        
    def test_TwoPenaltiesHasTwoPenaltyElements(self):
        self.mitigation.addPenalty(Penalty("asdf", 1, "asdf", Remediation("myId", "do this"), "asdf"))
        self.mitigation.addPenalty(Penalty("asdf", 1, "asdf", Remediation("myId", "do this"), "asdf"))
        self.assertEqual(len(self.mitigation.toElement().findall("./*/penalty")), 2)
    


class Test_W2W_CommunicationsAddReason(unittest.TestCase):
    def setUp(self):
        self.src = "src"
        self.dst = "dst"
        self.port = 12
        
        self.penalty = W2W_CommunicationPenalty(self.src, self.dst, self.port)
        
        
    def test_addReasonTakesSrcDstPortIsSuccessfullyAdded(self):
        beforeCount = len(self.penalty.reasons)
        self.penalty.addReason((1,2,3))
        
        self.assertEqual(len(self.penalty.reasons), beforeCount+1)
        
        
    def test_addReasonTakesNonSrcDstPortIsUnsuccessful(self):
        with self.assertRaises(InvalidW2WPenaltyReasonError):
            self.penalty.addReason(1)
            
    
    


class Test_W2W_CommunicationPenaltyToElement(unittest.TestCase):
    def setUp(self):
        self.src = "src"
        self.dst = "dst"
        self.port = 12
        
        self.penalty = W2W_CommunicationPenalty(self.src, self.dst, self.port)
    
    
    def tearDown(self):
        pass
    
    
    
    def test_PenaltyCreatesReasonChildElementWithThreeTuple(self):
        element = self.penalty.toElement()
        reasonChild = element.find("reason")
        
        self.assertIsNotNone(reasonChild)
        
        self.assertEqual(reasonChild.tag, "reason")
        self.assertEqual(reasonChild.text, "%s can talk to %s on port %d" % (self.src, self.dst, self.port))
        
    def test_PenaltyWithOneReasonHasOneReasonElementTag(self):
        element = self.penalty.toElement()
        self.assertEqual(len(element.findall("reason")), 1)
        
        
    def test_PenaltyWithTwoReasonHasTwoReasonElementTag(self):
        self.penalty.addReason((1,2,3))
        element = self.penalty.toElement()
        self.assertEqual(len(element.findall("reason")), 2)



class Test_SystemInfo(unittest.TestCase):
    def setUp(self):
        self.xml = """<?xml version="1.0" encoding="UTF-8"?>
                        <systemInfo>
                          <hostName>SYSTEM1</hostName>
                          <domainName>test.net</domainName>
                        </systemInfo>"""
                        
        self.noHostnameXml = """<?xml version="1.0" encoding="UTF-8"?>
                        <systemInfo>
                          <domainName>test.net</domainName>
                        </systemInfo>"""
                        
        self.noDomainNameXml = """<?xml version="1.0" encoding="UTF-8"?>
                        <systemInfo>
                        <hostName>SYSTEM1</hostName>
                          
                        </systemInfo>"""
                        
                        
    def tearDown(self):
        pass
    
    
    def test_goodXmlSystemInfoReturnsFqdn(self):
        sysInfo = SystemInfo(self.xml)
        self.assertEqual(sysInfo.getFqdn(), "SYSTEM1.test.net")

    def test_noHostnameElementThrowsInvalidSystemInfoError(self):
        with self.assertRaises(InvalidSystemInfoXmlError):
            SystemInfo(self.noHostnameXml)
            
            
    def test_noDomainNameElementThrowsInvalidSystemInfoError(self):
        with self.assertRaises(InvalidSystemInfoXmlError):
            SystemInfo(self.noDomainNameXml)
  
            

if __name__ == "__main__":
    unittest.main()