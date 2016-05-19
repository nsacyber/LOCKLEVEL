"""
Generate the penalty XML file used by the antivirus file reputation analyzer.
"""

import argparse
import xml.etree.ElementTree as ET
import xml.dom.minidom
import os
import sys

PENALTIES_ELEMENT = 'penalties'
PENALTY_ELEMENT = 'penalty'
REASON_ELEMENT = 'reason'
REMEDIATION_ELEMENT = 'remediation'

ID_ATTRIBUTE = 'id'
NAME_ATTRIBUTE = 'name'
VALUE_ATTRIBUTE = 'value'


class RemediationDefinition(object):
    """
    Represents a definition for a remediation.
    """

    def __init__(self, identifier, description):
        self.identifier = identifier
        self.description = description


class PenaltyDefinition(object):
    """
    Represents a definition for a penalty.
    """

    def __init__(self, identifier, name, value, reason, remediation):
        self.identifier = identifier
        self.name = name
        self.value = int(value)
        self.reason = reason
        self.remediation = remediation


def fixed_writexml(self, writer, indent='', addindent='', newl=''):
    """
    Ignore extra XML text elements when writing XML elements.
    """

    writer.write(indent+"<" + self.tagName)

    attrs = self._get_attributes()
    a_names = attrs.keys()
    a_names.sort()

    for a_name in a_names:
        writer.write(" %s=\"" % a_name)
        xml.dom.minidom._write_data(writer, attrs[a_name].value)
        writer.write("\"")

    if self.childNodes:
        if len(self.childNodes) == 1 and self.childNodes[0].nodeType == xml.dom.minidom.Node.TEXT_NODE:
            writer.write(">")
            self.childNodes[0].writexml(writer, "", "", "")
            writer.write("</%s>%s" % (self.tagName, newl))
            return

        writer.write(">%s" % (newl))

        for node in self.childNodes:
            if not node.nodeType == xml.dom.minidom.Node.TEXT_NODE:
                node.writexml(writer, indent+addindent, addindent, newl)

        writer.write("%s</%s>%s" % (indent, self.tagName, newl))
    else:
        writer.write("/>%s" % (newl))


def write_penalty_xml(path, penalties):
    """
    Write the penalties XML to the passed in path.
    """

    penalties_element = ET.Element(PENALTIES_ELEMENT)

    for penalty in penalties:
        penalty_element = ET.Element(PENALTY_ELEMENT)
        penalty_element.set(ID_ATTRIBUTE, penalty.identifier)
        penalty_element.set(NAME_ATTRIBUTE, penalty.name)
        penalty_element.set(VALUE_ATTRIBUTE, str(penalty.value))
        reason_element = ET.Element(REASON_ELEMENT)
        reason_element.text = penalty.reason
        penalty_element.append(reason_element)

        for remediation in penalty.remediation:
            remediation_element = ET.Element(REMEDIATION_ELEMENT)
            remediation_element.set(ID_ATTRIBUTE, remediation.identifier)
            remediation_element.text = remediation.description
            penalty_element.append(remediation_element)

        penalties_element.append(penalty_element)

    xml_string = ET.tostring(penalties_element, 'utf-8')
    reparsed = xml.dom.minidom.parseString(xml_string)
    pretty_xml = reparsed.toprettyxml(indent='\t', newl='\r\n', encoding='UTF-8')

    xml_file = open(path, "w")
    xml_file.write(pretty_xml)
    xml_file.close()


def get_penalties():
    """
    Get penalty definitions as a dictionary where the key is the penalty identifer and the value is the penalty object.
    """

    penalties = []

    penalty_id = 'DAT_OUTDATED'
    remediation = RemediationDefinition('UPDATE_DAT', 'Update the DAT file')
    penalty = PenaltyDefinition(penalty_id, 'DAT outdated', 50, 'DAT file version {0} published on {1} is {2} days old', [remediation])
    penalties.append(penalty)

    penalty_id = 'DAT_VERY_OUTDATED'
    remediation = RemediationDefinition('UPDATE_DAT', 'Update the DAT file')
    penalty = PenaltyDefinition(penalty_id, 'DAT very outdated', 100, 'DAT file version {0} published on {1} is {2} days old which is beyond the recommended value of {3} days', [remediation])
    penalties.append(penalty)

    penalty_id = 'ARTEMIS_SERVER_UNREACHABLE'
    remediation = RemediationDefinition('CHECK_ARTEMIS_CONNECTIVITY', 'Investigate GTI connectivity issues')
    penalty = PenaltyDefinition(penalty_id, 'artemis server unreachable', 100, 'Unable to resolve GTI server DNS address of {0}', [remediation])
    penalties.append(penalty)

    penalty_id = 'ARTEMIS_SERVER_UNEXPECTED'
    remediation = RemediationDefinition('CHECK_ARTMIS_CONFIGURATION', 'Confirm GTI network configuration is correct')
    penalty = PenaltyDefinition(penalty_id, 'artemis server unexpected', 50, 'The GTI server DNS address of {0} resolved to {1} which is not the expected value of {2}', [remediation])
    penalties.append(penalty)

    penalty_id = 'ARTEMIS_DISABLED'
    remediation = RemediationDefinition('ENABLE_ARTEMIS', 'Enable GTI')
    penalty = PenaltyDefinition(penalty_id, 'artemis disabled', 100, 'GTI is Disabled for the {0} component', [remediation])
    penalties.append(penalty)

    penalty_id = 'ARTEMIS_SENSITIVITY_LOW'
    remediation = RemediationDefinition('SET_ARTEMIS_SENSITIVITY_MEDIUM', 'Set the GTI Sensitivity Level to Medium or higher')
    penalty = PenaltyDefinition(penalty_id, 'artemis sensitivity low', 50, 'GTI Sensitivity Level is set to {0} which is below the recommended level of Medium for the {1} component', [remediation])
    penalties.append(penalty)

    penalty_id = 'ARTEMIS_SENSITIVITY_VERY_LOW'
    remediation = RemediationDefinition('SET_ARTEMIS_SENSITIVITY_MEDIUM', 'Set the GTI Sensitivity Level to Medium or higher')
    penalty = PenaltyDefinition(penalty_id, 'artemis sensitivity very low', 100, 'GTI Sensitivity Level is set to {0} which is far below the recommended level of Medium for the {1} component', [remediation])
    penalties.append(penalty)

    penalty_id = 'AV_ENGINE_OUTDATED'
    remediation = RemediationDefinition('UPDATE_AV_ENGINE', 'Update the AV engine to the latest supported version. See http://www.mcafee.com/us/support/support-eol-scan-engine.aspx for more information.')
    penalty = PenaltyDefinition(penalty_id, 'AV engine is outdated', 50, 'The AV engine version is {0} which is older than the latest supported engine version of {1}. Version 5600 and earlier are end of life.', [remediation])
    penalties.append(penalty)

    penalty_id = 'AV_ENGINE_VERY_OUTDATED'
    remediation = RemediationDefinition('UPDATE_AV_ENGINE', 'Update the AV engine to the latest supported version. See http://www.mcafee.com/us/support/support-eol-scan-engine.aspx for more information.')
    penalty = PenaltyDefinition(penalty_id, 'AV engine is very outdated', 100, 'The AV engine version is {0} which is older than the minimum recommended engine version of {1}. Version 5600 and earlier are end of life.', [remediation])
    penalties.append(penalty)

    penalty_id = 'VSE_OUTDATED'
    remediation = RemediationDefinition('UPDATE_OLD_VSE', 'Update VirusScan Enterprise to the latest recommended version. See https://kc.mcafee.com/corporate/index?page=content&id=kb51111 for more information.')
    penalty = PenaltyDefinition(penalty_id, 'VSE is outdated', 50, 'The VirusScan Enterprise version is {0} which is older than latest recommended version of {1}', [remediation])
    penalties.append(penalty)

    penalty_id = 'VSE_VERY_OUTDATED'
    remediation = RemediationDefinition('UPDATE_VERY_OLD_VSE', 'Update VirusScan Enterprise to the minimum recommended version. See https://kc.mcafee.com/corporate/index?page=content&id=kb51111 for more information.')
    penalty = PenaltyDefinition(penalty_id, 'VSE is very outdated', 100, 'The VirusScan Enterprise version is {0} which is older than minimum recommended version of {1}', [remediation])
    penalties.append(penalty)

    penalty_id = 'VSE_SERVICE_NOT_AUTOMATIC'
    remediation = RemediationDefinition('SET_VSE_SERVICE_AUTO', 'Change the VirusScan Enterprise service Startup Type to Automatic')
    penalty = PenaltyDefinition(penalty_id, 'VSE service is not automatically starting', 100, "The {0} service start mode is set to '{1}' rather than '{2}' so the system is not protected at the next boot", [remediation])
    penalties.append(penalty)

    penalty_id = 'VSE_SERVICE_NOT_RUNNING'
    remediation = RemediationDefinition('START_VSE_SERVICE', 'Start the VirusScan Enterprise service')
    penalty = PenaltyDefinition(penalty_id, 'VSE service is not running', 100, "The {0} service state is '{1}' rather than '{2}' so the system is not protected", [remediation])
    penalties.append(penalty)

    penalty_id = 'VSE_STARTUP_DISABLED'
    remediation = RemediationDefinition('ENABLE_VSE_STARTUP', 'Enable on access scanning at system startup')
    penalty = PenaltyDefinition(penalty_id, 'VSE startup is disabled', 100, 'VSE on access scanning at system startup is disabled', [remediation])
    penalties.append(penalty)

    penalty_id = 'VSE_NOT_INSTALLED'
    remediation = RemediationDefinition('INSTALL_VSE', 'Install VirusScan Enterprise')
    penalty = PenaltyDefinition(penalty_id, 'VSE is not installed', 100, "VirusScan Enterprise is not installed", [remediation])
    penalties.append(penalty)

    return penalties


def generate_penalty_xml(path):
    """
    Generate the penalty XML file at the given path.
    """
    penalties = get_penalties()

    write_penalty_xml(path, penalties)


def sanitize_arguments(args):
    """
    Sanitize arguments and return sane defaults
    """

    # try and use a penalties file in the same directory as the analyzer
    if args.penalty_xml is None:
        penalty_xml_file_path = os.path.join(os.getcwd(), 'penalties.xml')
    else:
        if os.path.exists(args.penalty_xml) and os.path.isfile(args.penalty_xml):
            penalty_xml_file_path = args.penalty_xml
        else:
            # passed in penalties file path was bad so try and use a penalties file in the same directory as the analyzer
            penalty_xml_file_path = os.path.join(os.getcwd(), 'penalties.xml')

    return os.path.abspath(penalty_xml_file_path)


def main():
    """
    Main function
    """

    xml.dom.minidom.Element.writexml = fixed_writexml

    # Parse program arguments
    parser = argparse.ArgumentParser(description='Generate the penalty XML file used by the antivirus file reputation analyzer.')
    parser.add_argument('-p', '--p', dest='penalty_xml', required=False, help='The path to create the penalties XML file. Optional. If not specifiedn then a penalties.xml file is created in the same location that the script is executing from.')

    args = parser.parse_args()

    penalty_xml_file_path = sanitize_arguments(args)

    generate_penalty_xml(penalty_xml_file_path)


if __name__ == "__main__":
    main()
