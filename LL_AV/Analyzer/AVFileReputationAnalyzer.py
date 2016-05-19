"""
Analyze collected results related to antivirus file reputation services.

Currently only McAfee antivirus is supported.
More products may be supported in the future.
"""

import logging
import fnmatch
import os
import datetime
import argparse
import sys
import zipfile
import xml.etree.ElementTree as ET
import xml.dom.minidom
import copy
import re
import shutil

AV_XML_FILE = 'll_av.xml'
SYSTEM_XML_FILE = 'll_systeminfo.xml'
ZIP_FILTER = '*.zip'

LOG_FILE = 'AVFileReputationAnalyzer_Errors.txt'
LOG_NAME = 'av_logger'

VALID_ARTEMIS_IP = '127.0.4.8'  # see McAfee KB53733

ARTEMIS_ENABLED_VALUE = 1

ARTEMIS_MEDIUM_VALUE = 2
ARTEMIS_LOW_VALUE = 1
ARTEMIS_VERY_LOW_VALUE = 0

SERVICE_RUNNING_VALUE = 4
SERVICE_AUTOMATIC_VALUE = 2

STARTUP_DISABLED_VALUE = 1

# minimum and recommended AV engine versions
MIN_AV_ENGINE_VER = '5700.0000'  # latest supported version
RECOMMEND_AV_ENGINE_VER = MIN_AV_ENGINE_VER  # 5600 and earlier are end of life

MIN_AV_PRODUCT_VER = '8.8.0.1385'  # VSE 8.8 Patch 5
RECOMMEND_AV_PRODUCT_VER = '8.8.0.1445'  # VSE 8.8 Patch 6

# maximum and recommended DAT age in days
MAX_AV_DAT_DAYS = 7
RECOMMEND_AV_DAT_DAYS = 2

# XML elements and attributes created by GetAVStatus.exe that are accessed
AV_ROOT_ELEMENT = 'll_av'
MCAFEE_ELEMENT = 'mcafeevse'
ARTEMIS_ELEMENT = 'artemis'
DNS_ELEMENT = 'dns'
QUERY_ELEMENT = 'query'
COMPONENT_ELEMENT = 'component'
LEVEL_ELEMENT = 'level'
ENABLED_ELEMENT = 'enabled'
SERVICE_ELEMENT = 'service'
STATE_ELEMENT = 'state'
START_ELEMENT = 'start'
DISABLED_ELEMENT = 'disabled'
DAT_ELEMENT = 'dat'
DATE_ELEMENT = 'date'
DAT_VER_MAJ_ELEMENT = 'versionmajor'
DAT_VER_MIN_ELEMENT = 'versionminor'
VER_ELEMENT = 'version'
AV_VER_MAJ_ELEMENT = 'avenginemajor'
AV_VER_MIN_ELEMENT = 'avengineminor'
PRODUCT_ELEMENT = 'product'
INSTALLED_ATTRIBUTE = 'installed'
MCAFEE_INSTALLED = './{0}[@{1}]'.format(MCAFEE_ELEMENT, INSTALLED_ATTRIBUTE)


# XML elements created by GetSystemInfo.exe that are accessed
SYSTEM_ELEMENT = 'systeminfo'

HOST_ELEMENT = 'hostname'
DOMAIN_ELEMENT = 'domainname'
IP4_ELEMENT = 'ip4address'
IP6_ELEMENT = 'ip6address'
MAC_ELEMENT = 'macaddress'
TIMESTAMP_ELEMENT = 'timestamp'
OS_NAME_ELEMENT = 'osname'
OS_VERSION_ELEMENT = 'osversion'
SERVICE_PACK_ELEMENT = 'servicepack'
PRODUCT_TYPE_ELEMENT = 'producttype'
OS_ARCH_ELEMENT = 'osarch'
HARD_ARCH_ELEMENT = 'hardarch'


# XML elements and attributes either read from the penalties XML 
# or written to the score XML file
PENALTIES_ELEMENT = 'penalties'
PENALTY_ELEMENT = 'penalty'
SCORE_ELEMENT = 'score'
REASON_ELEMENT = 'reason'
REMEDIATION_ELEMENT = 'remediation'
MITIGATION_ELEMENT = 'mitigation'
CUMULATIVE_ATTRIBUTE = 'cumulativeScore'
ID_ATTRIBUTE = 'id'
NAME_ATTRIBUTE = 'name'
VALUE_ATTRIBUTE = 'value'

AV_FILE_REP_VALUE = 'AVFileReputation'

# value that denotes a failure in reading data from a system by GetAVStatus.exe
FAILED = 'failed'

# list of penalty IDs defined in penalties.xml and in get_penalty_ids function
ARTEMIS_SERVER_UNREACHABLE_PENALTY_ID = 'ARTEMIS_SERVER_UNREACHABLE'
ARTEMIS_SERVER_UNEXPECTED_PENALTY_ID = 'ARTEMIS_SERVER_UNEXPECTED'
ARTEMIS_DISABLED_PENALTY_ID = 'ARTEMIS_DISABLED'
ARTEMIS_SENSITIVITY_LOW_PENALTY_ID = 'ARTEMIS_SENSITIVITY_LOW'
ARTEMIS_SENSITIVITY_VERY_LOW_PENALTY_ID = 'ARTEMIS_SENSITIVITY_VERY_LOW'
DAT_OUTDATED_PENALTY_ID = 'DAT_OUTDATED'
DAT_VERY_OUTDATED_PENALTY_ID = 'DAT_VERY_OUTDATED'
AV_ENGINE_OUTDATED_PENALTY_ID = 'AV_ENGINE_OUTDATED'
AV_ENGINE_VERY_OUTDATED_PENALTY_ID = 'AV_ENGINE_VERY_OUTDATED'
VSE_OUTDATED_PENALTY_ID = 'VSE_OUTDATED'
VSE_VERY_OUTDATED_PENALTY_ID = 'VSE_VERY_OUTDATED'
VSE_SERVICE_NOT_RUNNING_PENALTY_ID = 'VSE_SERVICE_NOT_RUNNING'
VSE_SERVICE_NOT_AUTOMATIC_PENALTY_ID = 'VSE_SERVICE_NOT_AUTOMATIC'
VSE_STARTUP_DISABLED_PENALTY_ID = 'VSE_STARTUP_DISABLED'
VSE_NOT_INSTALLED_PENALTY_ID = 'VSE_NOT_INSTALLED'


def get_penalty_ids():
    """
    Get the list of penalty IDs used by the analyzer.
    """
    return [ARTEMIS_SERVER_UNREACHABLE_PENALTY_ID, ARTEMIS_SERVER_UNEXPECTED_PENALTY_ID, ARTEMIS_DISABLED_PENALTY_ID, ARTEMIS_SENSITIVITY_LOW_PENALTY_ID, ARTEMIS_SENSITIVITY_VERY_LOW_PENALTY_ID, DAT_OUTDATED_PENALTY_ID, DAT_VERY_OUTDATED_PENALTY_ID,
            AV_ENGINE_OUTDATED_PENALTY_ID, AV_ENGINE_VERY_OUTDATED_PENALTY_ID, VSE_OUTDATED_PENALTY_ID, VSE_VERY_OUTDATED_PENALTY_ID, VSE_SERVICE_NOT_RUNNING_PENALTY_ID, VSE_SERVICE_NOT_AUTOMATIC_PENALTY_ID, VSE_STARTUP_DISABLED_PENALTY_ID,
            VSE_NOT_INSTALLED_PENALTY_ID]


def get_artemis_level_name(level):
    """
    Translate an artemis level number to a friendly level name.
    """

    return {
        0: 'Very Low',
        1: 'Low',
        2: 'Medium',
        3: 'High',
        4: 'Very High'
        }.get(level, 'Unknown')


def get_service_state_name(state):
    """
    Translate a Windows service run state number to a friendly service run state name.
    """

    return {
        1: 'Stopped',
        2: 'Start Pending',
        3: 'Stop Pending',
        4: 'Running',
        5: 'Continue Pending',
        6: 'Pause Pending',
        7: 'Paused'
        }.get(state, 'Unknown')


def get_service_start_name(start):
    """
    Translate a Windows service start number to a friendly service start name.
    """

    return {
        0: 'Boot',
        1: 'System',
        2: 'Automatic',
        3: 'Manual',
        4: 'Disabled'
        }.get(start, 'Unknown')


# start common code


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
    handler = logging.FileHandler(logpath)
    handler.setLevel(logging.ERROR)

    # Set up a stream handler that'll log to the console for testing purposes
    # Note: Debug is a lower level
    # so we can get more messages here than the file log will get
    stream = logging.StreamHandler()
    stream.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    stream.setFormatter(formatter)

    log.addHandler(handler)
    log.addHandler(stream)


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


class SystemInformation(object):
    """
    Represents system information.
    """

    def __init__(self, element):
        """System information class initializer"""

        self.hostname = ''
        self.domain = ''
        self.ipv4 = ''
        self.ipv6 = ''
        self.mac = ''
        self.timestamp = ''
        self.os_name = ''
        self.os_version = float(0.0)
        self.os_service_pack = 0
        self.os_product = ''
        self.os_arch = ''
        self.hard_arch = ''
        self.is64bit = False
        self.is_server = False

        self.hostname = get_element_text(element.find(HOST_ELEMENT))
        self.domain = get_element_text(element.find(DOMAIN_ELEMENT))
        self.ipv4 = get_element_text(element.find(IP4_ELEMENT))
        self.ipv6 = get_element_text(element.find(IP6_ELEMENT))
        self.mac = get_element_text(element.find(MAC_ELEMENT))

        timestamp_text = get_element_text(element.find(TIMESTAMP_ELEMENT))

        try:
            timestamp = datetime.datetime.strptime(timestamp_text, '%Y%m%d%H%M%S')
        except ValueError:
            timestamp = datetime.datetime.now()

        self.timestamp = timestamp

        self.os_name = get_element_text(element.find(OS_NAME_ELEMENT))

        version_text = get_element_text(element.find(OS_VERSION_ELEMENT))

        if version_text != '' and is_float('.'.join(version_text.split('.')[0:2])):
            self.os_version = float('.'.join(version_text.split('.')[0:2]))

        sp_text = get_element_text(element.find(SERVICE_PACK_ELEMENT))

        if sp_text != '' and is_int(sp_text):
            self.os_service_pack = int(sp_text)

        self.os_product = get_element_text(element.find(PRODUCT_TYPE_ELEMENT))

        self.os_arch = get_element_text(element.find(OS_ARCH_ELEMENT))

        self.hard_arch = get_element_text(element.find(HARD_ARCH_ELEMENT))

        if self.os_product != '' and ('server' == self.os_product or 'domain controller' == self.os_product):
            self.is_server = True

        if self.os_arch.lower() != 'x86':
            self.is64bit = True


def calculate_multiplicative_score(penalties):
    """
    Calculate a multiplicate score on the passed in penalties.
    """

    cumulative_score = 9

    for penalty in penalties:
        current_score = 100 - penalty.value
        cumulative_score = cumulative_score * (current_score/100.0)

    cumulative_score = cumulative_score + 1
    cumulative_score = round(cumulative_score, 1)

    return cumulative_score


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


def read_penalty_definitions(path):
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


def fixed_writexml(self, writer, indent='', addindent='', newl=''):
    """
    Ignore extra XML text elements when writing XML elements.
    """

    writer.write(indent+'<' + self.tagName)

    attrs = self._get_attributes()
    a_names = attrs.keys()
    a_names.sort()

    for a_name in a_names:
        writer.write(' %s="' % a_name)
        xml.dom.minidom._write_data(writer, attrs[a_name].value)
        writer.write('"')

    if self.childNodes:
        if len(self.childNodes) == 1 and self.childNodes[0].nodeType == xml.dom.minidom.Node.TEXT_NODE:
            writer.write('>')
            self.childNodes[0].writexml(writer, '', '', '')
            writer.write('</%s>%s' % (self.tagName, newl))
            return

        writer.write('>%s' % (newl))

        for node in self.childNodes:
            if not node.nodeType == xml.dom.minidom.Node.TEXT_NODE:
                node.writexml(writer, indent+addindent, addindent, newl)

        writer.write('%s</%s>%s' % (indent, self.tagName, newl))
    else:
        writer.write('/>%s' % (newl))


def write_score_xml(path, penalties, systemxmlpath, name):
    """
    Write the analyzer score XML, penalties, and system information to the passed in path.
    """

    system_tree = ET.parse(systemxmlpath)
    system_root = system_tree.getroot()

    mitigation_element = ET.Element(MITIGATION_ELEMENT)
    mitigation_element.set(NAME_ATTRIBUTE, name)
    mitigation_element.append(system_root)

    cumulative_score = calculate_multiplicative_score(penalties)

    score_element = ET.Element(SCORE_ELEMENT)
    score_element.set(CUMULATIVE_ATTRIBUTE, str(cumulative_score))

    if not cumulative_score == 10:
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

            score_element.append(penalty_element)

    mitigation_element.append(score_element)

    xml_string = ET.tostring(mitigation_element, 'utf-8')
    reparsed = xml.dom.minidom.parseString(xml_string)
    pretty_xml = reparsed.toprettyxml(indent='\t', newl='\r\n', encoding='UTF-8')

    xml_file = open(path, 'w')
    xml_file.write(pretty_xml)
    xml_file.close()


def get_element_text(element):
    """
    Returns the text value of an element.
    """

    text = ''

    if element is not None and element.__class__ is ET.Element:
        if element.text is not None:
            text = element.text.strip()

    return text


def is_int(value):
    """
    Tests if a value can be converted to an integer.
    """

    isint = False

    try:
        int(value)
        isint = True
    except ValueError:
        pass

    return isint


def is_float(value):
    """
    Tests if a value can be converted to a float.
    """

    isfloat = False

    try:
        float(value)
        isfloat = True
    except ValueError:
        pass

    return isfloat


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


def get_zip_files(path, recurse=False):
    """
    Get all zip files from the path.
    """

    zips = []

    if recurse:
        for root, dirs, files in os.walk(path):
            for filename in files:
                if fnmatch.fnmatch(filename, ZIP_FILTER):
                    zips.append(os.path.join(root, filename))
    else:
        zips = [os.path.join(path, filename) for filename in os.listdir(path) if os.path.splitext(filename)[1][1:] == 'zip']

    return zips


def expand_zip_file(zipfilepath, extractpath):
    """
    Expand a zip file to a path.
    """
    archive = zipfile.ZipFile(zipfilepath, 'r')

    if not os.path.exists(extractpath):
        os.makedirs(extractpath)

    archive.extractall(extractpath)
    archive.close()

# end common code


def get_artemis_query_penalties(artemiselement, penalties):
    """
    Apply penalties for artemis, aka Global Threat Intelligence, DNS queries.
    """
    applied_penalties = []

    if artemiselement is not None:
        dns_element = artemiselement.find(DNS_ELEMENT)

        if dns_element is not None:
            query_elements = dns_element.findall(QUERY_ELEMENT)

            if query_elements is not None:
                for query_element in query_elements:
                    query = query_element.attrib[NAME_ATTRIBUTE]  # check for None
                    query_result = get_element_text(query_element)

                    if query_result.lower().startswith(FAILED):
                        penalty = copy.deepcopy(penalties[ARTEMIS_SERVER_UNREACHABLE_PENALTY_ID])
                        penalty.reason = penalty.reason.format(query)
                        applied_penalties.append(penalty)
                    elif not query_result == VALID_ARTEMIS_IP:
                        penalty = copy.deepcopy(penalties[ARTEMIS_SERVER_UNEXPECTED_PENALTY_ID])
                        penalty.reason = penalty.reason.format(query, query_result, VALID_ARTEMIS_IP)
                        applied_penalties.append(penalty)

    return applied_penalties


def get_artemis_component_penalties(artemiselement, penalties):
    """
    Apply penalties for components that can be configured to use artemis, aka Global Threat Intelligence.
    """

    applied_penalties = []

    if artemiselement is not None:
        artemis_component_elements = artemiselement.findall(COMPONENT_ELEMENT)

        if artemis_component_elements is not None:
            for artemis_component_element in artemis_component_elements:
                component_name = artemis_component_element.attrib[NAME_ATTRIBUTE]

                enabled_element = artemis_component_element.find(ENABLED_ELEMENT)
                level_element = artemis_component_element.find(LEVEL_ELEMENT)

                if enabled_element is not None and level_element is not None:
                    enabled_text = get_element_text(enabled_element)
                    level_text = get_element_text(level_element)

                    if not enabled_text.lower().startswith(FAILED) and not level_text.lower().startswith(FAILED):
                        if is_int(enabled_text) and is_int(level_text):
                            artemis_enabled = (int(enabled_text) == ARTEMIS_ENABLED_VALUE)
                            artemis_level = int(level_text)

                            if not artemis_enabled:
                                penalty = copy.deepcopy(penalties[ARTEMIS_DISABLED_PENALTY_ID])
                                penalty.reason = penalty.reason.format(component_name)
                                applied_penalties.append(penalty)

                            # STIG says must be Medium
                            if artemis_level < ARTEMIS_MEDIUM_VALUE:
                                level_name = get_artemis_level_name(artemis_level)

                                if artemis_level == ARTEMIS_VERY_LOW_VALUE:
                                    penalty = copy.deepcopy(penalties[ARTEMIS_SENSITIVITY_VERY_LOW_PENALTY_ID])
                                    penalty.reason = penalty.reason.format(level_name, component_name)
                                    applied_penalties.append(penalty)
                                elif artemis_level == ARTEMIS_LOW_VALUE:
                                    penalty = copy.deepcopy(penalties[ARTEMIS_SENSITIVITY_LOW_PENALTY_ID])
                                    penalty.reason = penalty.reason.format(level_name, component_name)
                                    applied_penalties.append(penalty)
                        else:
                            log.error("enabled (%s) or level (%s) was not an integer value", enabled_text, level_text)

    return applied_penalties


def get_artemis_penalties(parentelement, penalties):
    """
    Apply penalties for artemis, aka Global Threat Intelligence, information.
    """

    applied_penalties = []

    artemis_element = parentelement.find(ARTEMIS_ELEMENT)

    if artemis_element is not None:
        applied_penalties.extend(get_artemis_query_penalties(artemis_element, penalties))

        applied_penalties.extend(get_artemis_component_penalties(artemis_element, penalties))

    return applied_penalties


def get_service_penalties(parentelement, penalties):
    """
    Apply penalties for service inforation.
    """

    applied_penalties = []

    service_element = parentelement.find(SERVICE_ELEMENT)

    if service_element is not None:
        service_name = service_element.attrib[NAME_ATTRIBUTE]

        state_element = service_element.find(STATE_ELEMENT)
        start_element = service_element.find(START_ELEMENT)

        if state_element is not None and start_element is not None:
            state_text = get_element_text(state_element)
            start_text = get_element_text(start_element)

            if is_int(state_text) and is_int(start_text):
                if not int(state_text) == SERVICE_RUNNING_VALUE:
                    state_name = get_service_state_name(int(state_text))
                    penalty = copy.deepcopy(penalties[VSE_SERVICE_NOT_RUNNING_PENALTY_ID])
                    penalty.reason = penalty.reason.format(service_name, state_name, get_service_state_name(SERVICE_RUNNING_VALUE))
                    applied_penalties.append(penalty)

                if not int(start_text) == SERVICE_AUTOMATIC_VALUE:
                    start_name = get_service_start_name(int(start_text))
                    penalty = copy.deepcopy(penalties[VSE_SERVICE_NOT_AUTOMATIC_PENALTY_ID])
                    penalty.reason = penalty.reason.format(service_name, start_name, get_service_start_name(SERVICE_AUTOMATIC_VALUE))
                    applied_penalties.append(penalty)
            else:
                log.error("state (%s) or start (%s) was not an integer value", state_text, start_text)

        disabled_element = service_element.find(DISABLED_ELEMENT)

        if disabled_element is not None:
            disabled_text = get_element_text(disabled_element)

            if is_int(disabled_text):
                if int(disabled_text) == STARTUP_DISABLED_VALUE:
                    penalty = penalties[VSE_STARTUP_DISABLED_PENALTY_ID]
                    applied_penalties.append(penalty)
            else:
                log.error("startup disabled (%s) was not an integer value", disabled_text)

    return applied_penalties


def get_dat_penalties(parentelement, penalties, collectiondate):
    """
    Apply penalties for DAT file information.
    """

    applied_penalties = []

    dat_element = parentelement.find(DAT_ELEMENT)

    if dat_element is not None:
        date_element = dat_element.find(DATE_ELEMENT)
        version_major_element = dat_element.find(DAT_VER_MAJ_ELEMENT)
        version_minor_element = dat_element.find(DAT_VER_MIN_ELEMENT)

        if date_element is not None and version_major_element is not None and version_minor_element is not None:
            date_text = get_element_text(date_element)
            version_major_text = get_element_text(version_major_element)
            version_minor_text = get_element_text(version_minor_element)

            if not date_text.lower().startswith(FAILED) and not version_major_text.lower().startswith(FAILED) and not version_minor_text.lower().startswith(FAILED):
                try:
                    dat_date = datetime.datetime.strptime(date_text, '%Y/%m/%d')

                    # ignore the collection date hour, minute, and second parts since the DAT date only has month, day, and year
                    compare_date = datetime.datetime(collectiondate.year, collectiondate.month, collectiondate.day)

                    dat_days = abs((compare_date - dat_date).days)

                    dat_version = "{0:0>4d}.{1:0>4d}".format(int(version_major_text), int(version_minor_text))

                    formatted_dat_date = dat_date.strftime("%m/%d/%Y")

                    if dat_days > MAX_AV_DAT_DAYS:
                        penalty = copy.deepcopy(penalties[DAT_VERY_OUTDATED_PENALTY_ID])
                        penalty.reason = penalty.reason.format(dat_version, formatted_dat_date, dat_days, MAX_AV_DAT_DAYS)
                        applied_penalties.append(penalty)
                    elif dat_days > RECOMMEND_AV_DAT_DAYS:
                        penalty = copy.deepcopy(penalties[DAT_OUTDATED_PENALTY_ID])
                        penalty.reason = penalty.reason.format(dat_version, formatted_dat_date, dat_days)
                        applied_penalties.append(penalty)
                except Exception as error:
                    log.exception("exception %s parsing DAT date", error)

    return applied_penalties


def normalize_version(version):
    """
    Normalize a version string by removing extra zeroes and periods.
    """

    return [int(x) for x in re.sub(r'(\.0+)*$', '', version).split('.')]


def compare_version(version1, version2):
    """
    Compare to version strings for equality.
    """

    normalized_version1 = normalize_version(version1)
    normalized_version2 = normalize_version(version2)
    return cmp(normalized_version1, normalized_version2)


def get_version_penalties(parentelement, penalties):
    """
    Apply penalties for product and AV version information.
    """

    applied_penalties = []

    version_element = parentelement.find(VER_ELEMENT)

    if version_element is not None:
        av_engine_major_element = version_element.find(AV_VER_MAJ_ELEMENT)
        av_engine_minor_element = version_element.find(AV_VER_MIN_ELEMENT)

        if av_engine_major_element is not None and av_engine_minor_element is not None:
            av_engine_major_text = get_element_text(av_engine_major_element)
            av_engine_minor_text = get_element_text(av_engine_minor_element)

            if not av_engine_major_text.lower().startswith(FAILED) and not av_engine_minor_text.lower().startswith(FAILED):
                if is_int(av_engine_major_text) and is_int(av_engine_minor_text):
                    found_engine_version = "{0:0>4d}.{1:0>4d}".format(int(av_engine_major_text), int(av_engine_minor_text))

                    # the found engine version should be the same or newer than the version we're checking against
                    if compare_version(found_engine_version, MIN_AV_ENGINE_VER) < 0:
                        penalty = copy.deepcopy(penalties[AV_ENGINE_VERY_OUTDATED_PENALTY_ID])
                        penalty.reason = penalty.reason.format(found_engine_version, MIN_AV_ENGINE_VER)
                        applied_penalties.append(penalty)
                    elif compare_version(found_engine_version, RECOMMEND_AV_ENGINE_VER) < 0:
                        penalty = copy.deepcopy(penalties[AV_ENGINE_OUTDATED_PENALTY_ID])
                        penalty.reason = penalty.reason.format(found_engine_version, RECOMMEND_AV_ENGINE_VER)
                        applied_penalties.append(penalty)
                else:
                    log.error("AV engine major (%s) or AV engine minor (%s) was not an integer value", av_engine_major_text, av_engine_minor_text)

        product_element = version_element.find(PRODUCT_ELEMENT)

        if product_element is not None:
            product_text = get_element_text(product_element)

            if not product_text.lower().startswith(FAILED):
                if compare_version(product_text, MIN_AV_PRODUCT_VER) < 0:
                    penalty = copy.deepcopy(penalties[VSE_VERY_OUTDATED_PENALTY_ID])
                    penalty.reason = penalty.reason.format(product_text, MIN_AV_PRODUCT_VER)
                    applied_penalties.append(penalty)
                elif compare_version(product_text, RECOMMEND_AV_PRODUCT_VER) < 0:
                    penalty = copy.deepcopy(penalties[VSE_OUTDATED_PENALTY_ID])
                    penalty.reason = penalty.reason.format(product_text, RECOMMEND_AV_PRODUCT_VER)
                    applied_penalties.append(penalty)

    return applied_penalties


def get_applied_penalties(path, systempath, penalties):
    """
    Get all penalties that apply to the collected information.
    """

    applied_penalties = []
    av_tree = None
    sysinfo_tree = None
    sysinfo = None
    installed = False

    try:
        av_tree = ET.parse(path)
    except Exception as error:
        log.exception('Unable to load %s due to an error of %s', systempath, error)

    # todo remove this because it is duplicative
    try:
        sysinfo_tree = ET.parse(systempath)
    except Exception as error:
        log.exception('Unable to load %s due to an error of %s', systempath, error)

    if av_tree is not None:
        # since find/findall aren't case insensitive and XPath support is limited, force all element and attribute names to lower case
        av_tree = lower_tree(av_tree)
        sysinfo_tree = lower_tree(sysinfo_tree)

        av_root = av_tree.getroot()
        sysinfo_element = sysinfo_tree.getroot()

        sysinfo = SystemInformation(sysinfo_element)

        mcafee_element = av_root.find(MCAFEE_INSTALLED)

        if mcafee_element is not None:
            installed = mcafee_element.attrib[INSTALLED_ATTRIBUTE].lower() == 'true'

        if installed:
            applied_penalties.extend(get_artemis_penalties(mcafee_element, penalties))

            applied_penalties.extend(get_service_penalties(mcafee_element, penalties))

            applied_penalties.extend(get_dat_penalties(mcafee_element, penalties, sysinfo.timestamp))

            applied_penalties.extend(get_version_penalties(mcafee_element, penalties))
        else:
            penalty = penalties[VSE_NOT_INSTALLED_PENALTY_ID]
            applied_penalties.append(penalty)

    return applied_penalties


def analyze(inputdirectorypath, outputdirectorypath, penaltyxmlfilepath):
    """
    Execute main analyzer logic.
    """

    penalty_definitions = dict()
    applied_penalties = []

    # make sure the penalty XML file at least parses correctly from an XML standpoint
    try:
        penalty_definitions = read_penalty_definitions(penaltyxmlfilepath)
    except Exception as error:
        log.exception('Unable to load penalties file from %s due to an error of %s', penaltyxmlfilepath, error)
        sys.exit(-1)

    # make sure the penalty IDs that are used in the analyzer are in the loaded penalties
    if not set(get_penalty_ids()).issubset(set(penalty_definitions)):
        missing = set(get_penalty_ids()).difference(set(penalty_definitions))
        log.error('Missing required penalty IDs: %s', (', '.join(missing)))
        sys.exit(-1)

    zip_files = get_zip_files(inputdirectorypath)

    for zip_file in zip_files:
        extract_path = zip_file.rsplit('.', 1)[0]
        extract_path = extract_path.replace(inputdirectorypath, outputdirectorypath)

        expand_zip_file(zip_file, extract_path)

        av_xml_path = os.path.join(extract_path, AV_XML_FILE)
        system_xml_path = os.path.join(extract_path, SYSTEM_XML_FILE)

        if os.path.exists(av_xml_path) and os.path.exists(system_xml_path):
            try:
                applied_penalties = get_applied_penalties(av_xml_path, system_xml_path, penalty_definitions)

                write_score_xml('.'.join([extract_path, 'xml']), applied_penalties, system_xml_path, AV_FILE_REP_VALUE)
            except Exception as error:
                log.exception('Unexpected error %s while processing system', error)
        else:
            if not os.path.exists(av_xml_path):
                log.error('%s did not exist', av_xml_path)

            if not os.path.exists(system_xml_path):
                log.error('%s did not exist', system_xml_path)


def sanitize_arguments(args):
    """
    Sanitize arguments and return sane defaults.
    """

    if not os.path.exists(os.path.abspath(args.input_directory_path)):
        log.error('Input path of %s does not exist', os.path.abspath(args.input_directory_path))
        sys.exit(-1)

    if not os.path.isdir(os.path.abspath(args.input_directory_path)):
        log.error('Input path of %s is not a directory', os.path.abspath(args.input_directory_path))
        sys.exit(-1)

    # try and use a penalties file in the same directory as the analyzer
    if args.penalty_xml is None:
        penalty_xml_file_path = os.path.join(os.getcwd(), 'penalties.xml')
    else:
        if os.path.exists(os.path.abspath(args.penalty_xml)) and os.path.isfile(os.path.abspath(args.penalty_xml)):
            penalty_xml_file_path = os.path.abspath(args.penalty_xml)
        else:
            # passed in penalties file path was bad so try and use a penalties file in the same directory as the analyzer
            penalty_xml_file_path = os.path.abspath(os.path.join(os.getcwd(), 'penalties.xml'))

    if os.path.exists(penalty_xml_file_path) and os.path.isfile(penalty_xml_file_path):
        pass
    else:
        log.error('Unable to load penalty XML file from %s', penalty_xml_file_path)
        sys.exit(-1)

    return (os.path.abspath(args.input_directory_path), os.path.abspath(args.output_directory_path), os.path.abspath(penalty_xml_file_path))


def main():
    """
    Main function.
    """

    log_path = os.path.abspath(LOG_FILE)

    setup_logging(log_path, LOG_NAME)

    xml.dom.minidom.Element.writexml = fixed_writexml

    # Parse program arguments
    parser = argparse.ArgumentParser(description='Executes the LOCKLEVEL Antivirus File Reputation analyzer')
    parser.add_argument('-i', '--i', help='The path to the input directory.', dest='input_directory_path', required=True)
    parser.add_argument('-o', '--o', help='The path to the output directory.', dest='output_directory_path', required=True)
    parser.add_argument('-p', '--p', help='The path to the penalties XML file. Optional. If not specified, then a penalties.xml file is looked for in the same location that the script is executing from.', dest='penalty_xml', required=False)

    args = parser.parse_args()

    input_directory_path, output_directory_path, penalty_xml_file_path = sanitize_arguments(args)

    if os.path.exists(output_directory_path) and os.path.isdir(output_directory_path) and output_directory_path != os.getcwd():
        shutil.rmtree(output_directory_path, ignore_errors=True)

    os.mkdir(output_directory_path)

    analyze(input_directory_path, output_directory_path, penalty_xml_file_path)

    cleanup_logging(log_path, LOG_NAME)

if __name__ == "__main__":
    main()
