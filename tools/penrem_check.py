"""
Finds all penalties.xml files and checks them for duplicate penalties and remediations.
Generates a master.xml file that contains all penalties and a remediations.js file used by the presentation layer.
"""

import os
import sys
import argparse
import fnmatch
import xml.etree.ElementTree as ET
import xml.dom.minidom
import json


PENALTIES_ELEMENT = 'penalties'
PENALTY_ELEMENT = 'penalty'
REASON_ELEMENT = 'reason'
REMEDIATION_ELEMENT = 'remediation'

ID_ATTRIBUTE = 'id'
NAME_ATTRIBUTE = 'name'
VALUE_ATTRIBUTE = 'value'


class RemediationEncoder(json.JSONEncoder):
    """
	Encode a remediation correctly.
	"""
    def default(self, o):
        return o.__dict__


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


def lower_tree(tree):
    """
    Change all element names and attribute names to lower case.
    """

    root = tree.getroot()

    for node in root.iter():
        node.tag = node.tag.lower()

        attributes = dict()

        for attribute in node.attrib:
            attributes[attribute.lower()] = node.attrib[attribute]

        node.attrib = attributes

    tree._setroot(root)

    return tree


def get_element_text(element):
    """
    Returns the text value of an element.
    """

    text = ''

    if element.__class__ is ET.Element is ET.Element:
        if element is not None:
            if element.text is not None:
                text = element.text

    return text


def read_penalty_xml(path):
    """
    Read the penalties file from the passed in path.
    Return a dictionary where the key is the penalty ID and the value is the penalty object.
    """

    penalties = dict()

    tree = ET.parse(path)

    tree = lower_tree(tree)

    root = tree.getroot()

    if root is not None and root.tag == PENALTIES_ELEMENT:
        for penalty in root.findall(PENALTY_ELEMENT):
            penalty_id = penalty.attrib[ID_ATTRIBUTE]
            name = penalty.attrib[NAME_ATTRIBUTE]
            value = int(penalty.attrib[VALUE_ATTRIBUTE])

            reason_element = penalty.find(REASON_ELEMENT)
            reason = get_element_text(reason_element)

            remediations = []

            for remediation_element in penalty.findall(REMEDIATION_ELEMENT):
                remediation_id = remediation_element.attrib[ID_ATTRIBUTE]
                description = get_element_text(remediation_element)
                remediation = RemediationDefinition(remediation_id, description)
                remediations.append(remediation)

            penalty = PenaltyDefinition(penalty_id, name, value, reason, remediations)

            if penalty_id not in penalties:
                penalties[penalty_id] = penalty

    return penalties


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


def get_files(path, pattern):
    """
    Get all matching files from the path.
    """

    matching_files = []

    for root, dirs, files in os.walk(path):
        for filename in files:
            if fnmatch.fnmatch(filename, pattern):
                matching_files.append(os.path.join(root, filename))

    return matching_files


def generate_penalties(inputdirectorypath, outputdirectorypath, filename):
    """
    Generate master penalties.xml file.
    """

    penalty_definitions = []

    xml_files = get_files(inputdirectorypath, "*penalties.xml")

    for xml_file in xml_files:
        xml_file = os.path.abspath(xml_file)

        penalties = read_penalty_xml(xml_file)

        for penalty_id, penalty in penalties.iteritems():
            penalty_definitions.append(penalty)

    write_penalty_xml(os.path.join(outputdirectorypath, filename), penalty_definitions)


def generate_remediations(inputdirectorypath, outputdirectorypath, filename, pretty=False):
    """
    Generate remediations.js file used by presentation layer.
    """

    remediation_definitions = {}

    xml_files = get_files(inputdirectorypath, "*penalties.xml")

    for xml_file in xml_files:
        xml_file = os.path.abspath(xml_file)

        penalties = read_penalty_xml(xml_file)

        for penalty_id, penalty in penalties.iteritems():
            remediations = penalty.remediation

            for remediation in remediations:
                if remediation.identifier not in remediation_definitions:
                    remediation_definitions[remediation.identifier] = remediation

    indent = 4 if pretty else None

    with open(os.path.join(outputdirectorypath, filename), 'w') as json_file:
        json_file.write('var remediationDefinitions = ')
        json.dump(remediation_definitions, json_file, ensure_ascii=True, indent=indent, separators=(',', ':'), cls=RemediationEncoder)


def check_penalties(inputdirectorypath):
    """
    Check for duplicate penalties.
    """

    penalty_definitions = {}
    duplicates = []

    xml_files = get_files(inputdirectorypath, "*penalties.xml")

    for xml_file in xml_files:
        xml_file = os.path.abspath(xml_file)

        penalties = read_penalty_xml(xml_file)

        for penalty_id, penalty in penalties.iteritems():
            if penalty_id not in penalty_definitions:
                penalty_definitions[penalty_id] = (penalty, xml_file)
            else:
                original_penalty, original_xml_file = penalty_definitions[penalty_id]
                duplicates.append((penalty_id, original_xml_file, xml_file))

    return duplicates


def check_remediations(inputdirectorypath):
    """
    Check for duplicate remediations.
    """

    remediation_definitions = {}
    remediation_descriptions = {}
    duplicates = []

    xml_files = get_files(inputdirectorypath, "*penalties.xml")

    for xml_file in xml_files:
        xml_file = os.path.abspath(xml_file)

        penalties = read_penalty_xml(xml_file)

        for penalty_id, penalty in penalties.iteritems():
            remediations = penalty.remediation

            for remediation in remediations:
                if remediation.identifier not in remediation_definitions:
                    remediation_definitions[remediation.identifier] = (remediation, xml_file)
                else:
                    original_remediation, original_xml_file = remediation_definitions[remediation.identifier]

                    # same remediation ID as one that's already been seen except the descriptions do not match
                    if original_remediation.description != remediation.description:
                        print "same remediation id but different description found.\r\ncommon rem id: %s\r\noriginal desc: %s\r\ncurrent desc: %s\r\noriginal file: %s\r\ncurrent file: %s" % (original_remediation.identifier, original_remediation.description, remediation.description, original_xml_file, xml_file)
                        print ""
                        duplicates.append((original_remediation.identifier, original_remediation.description, remediation.description, original_xml_file, xml_file))

                if remediation.description not in remediation_descriptions:
                    remediation_descriptions[remediation.description] = (remediation, xml_file)
                else:
                    original_remediation, original_xml_file = remediation_descriptions[remediation.description]

                    if original_remediation.identifier != remediation.identifier:
                        print "same remediation description but different id found.\r\ncommon rem desc: %s\r\noriginal id: %s\r\ncurrentid: %s\r\noriginal file: %s\r\ncurrent file: %s" % (original_remediation.description, original_remediation.identifier, remediation.identifier, original_xml_file, xml_file)
                        print ""
                        duplicates.append((original_remediation.description, original_remediation.identifier, remediation.identifier, original_xml_file, xml_file))

    return duplicates


def main():
    """
    Main function.
    """

    # Parse program arguments
    parser = argparse.ArgumentParser(description='Generates a remediations.js data file LOCKLEVEL presentation')
    parser.add_argument('-i', '--i', help='The path to the input directory that holds the penalty files.', dest='input_directory_path', required=True)
    parser.add_argument('-o', '--o', help='The path to the output directory to write the generated content to.', dest='output_directory_path', required=True)

    args = parser.parse_args()

    if not os.path.exists(args.input_directory_path):
        sys.exit('Input path of {0} does not exist'.format(args.input_directory_path))

    if not os.path.isdir(args.input_directory_path):
        sys.exit('Input path of {0} is not a directory'.format(args.input_directory_path))

    input_directory_path = os.path.abspath(args.input_directory_path)
    output_directory_path = os.path.abspath(args.output_directory_path)

    duplicate_remediations = check_remediations(input_directory_path)

    if len(duplicate_remediations) > 0:
        for common, original, duplicate, original_file, duplicate_file in duplicate_remediations:
            print "same remediation id but different description found.\r\ncommon: %s\r\noriginal: %s\r\nduplicate: %s\r\noriginal file: %s\r\nduplicate file: %s" % (common, original, duplicate, original_file, duplicate_file)
            print ""

        raise Exception("duplicate remediations found")

    duplicate_penalties = check_penalties(input_directory_path)

    if len(duplicate_penalties) > 0:
        for identifier, original_file, duplicate_file in duplicate_penalties:
            print "duplicate penalty id: %s found in %s and %s" % (identifier, original_file, duplicate_file)
            print ""

        raise Exception("duplicate penalties found")

    generate_remediations(input_directory_path, output_directory_path, "remediations.js", False)

    generate_penalties(input_directory_path, output_directory_path, "master.xml")

if __name__ == "__main__":
    main()
