"""
@summary: This is a LOCKLEVEL analyzer for scoring a system's
anti-exploitation mitigations. It takes optional parameters
        -i <input directory>
        -o <output directory>
        -p <path penalties xml file>
If these parameters are not specified, it assumes these items are in
the current working directory.
"""

import sys
import logging
import os
import shutil
import copy
import xml.etree.ElementTree as ET
import xml.dom.minidom
import fnmatch
import datetime
import argparse
import zipfile

AE_XML_FILE = 'll_ae.xml'
SYSTEM_XML_FILE = 'll_systeminfo.xml'
ZIP_FILTER = '*.zip'

LOG_FILE = 'AntiExploitationAnalyzer_Errors.txt'
LOG_NAME = 'ae_logger'

DEP_ALWAYS_ON_TEXT = 'AlwaysOn'
DEP_ALWAYS_OFF_TEXT = 'AlwaysOff'
DEP_OPT_IN_TEXT = 'OptIn'
DEP_OPT_OUT_TEXT = 'OptOut'
DEP_APPCOMPAT_DISABLE_HIDE_TEXT = 'DISABLENXHIDEUI'
DEP_APPCOMPAT_DISABLE_SHOW_TEXT = 'DISABLENXSHOWUI'

WINTRUST_CONFIG_32 = r'HKLM\Software\Microsoft\Cryptography\Wintrust\Config'
WINTRUST_CONFIG_64 = r'HKLM\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config'

# XML elements and attributes created by AntiExploitation.exe that are accessed
HW_SUPPORT_ELEMENT = 'hardwaresupport'
PAE_ELEMENT = 'pae'
NX_ELEMENT = 'nx'
SMEP_ELEMENT = 'smep'
SMAP_ELEMENT = 'smap'
SYS_MITS_ELEMENT = 'systemmitigations'
CFG_ELEMENT = 'cfg'
FIRMWARE_TYPE_ELEMENT = 'firmwaretype'
SECURE_BOOT_ELEMENT = 'secureboot'
FONT_BLOCKING_ELEMENT = 'fontblocking'
DEP_POLICY_ELEMENT = 'deppolicy'
MIT_OPTS_ELEMENT = 'mitigationoptions'
APP_MITS_ELEMENT = 'appmitigations'

DLLCHARACTERISTICS_ELEMENT = 'dllcharacteristics'
EXEC_OPTS_ELEMENT = 'executeoptions'
APP_COMPAT_ELEMENT = 'appcompat'
MOVE_IMAGES_ELEMENT = 'moveimages'
DECV_ELEMENT = 'disableexceptionchainvalidation'
KSEHOP_ELEMENT = 'kernelsehopenabled'
NULL_PAGE_ELEMENT = 'abletomapnullpage'
HOTFIXES_ELEMENT = 'hotfixes'
HOTFIX_ELEMENT = 'hotfix'
LOW_VA_ELEMENT = 'enablelowvaaccess'
CERT_PADDING_ELEMENT = 'enablecertpaddingcheck'
CERT_PADDING_ELEMENT64 = 'enablecertpaddingcheck_wow64'
SECURE_SEARCH_ELEMENT = 'cwdillegalindllsearch'
AE_ELEMENT = 'antiexploitation'

PATH_ATTRIBUTE = 'path'
MACHINE_ATTRIBUTE = 'machine'

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

AE_VALUE = 'AntiExploitation'

# IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
# IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
# IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
# IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000
# IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000

# IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_IA64 = 0x0200
IMAGE_FILE_MACHINE_AMD64 = 0x8664


# list of penalty IDs defined in penalties.xml and in get_penalty_ids function
HW_NO_SMEP_PENALTY_ID = 'HW_NO_SMEP'
HW_NO_SMAP_PENALTY_ID = 'HW_NO_SMAP'
OS_NO_SMEP_PENALTY_ID = 'OS_NO_SMEP'
OS_NO_SMAP_PENALTY_ID = 'OS_NO_SMAP'
OS_NO_SECURE_BOOT_PENALTY_ID = 'OS_NO_SECURE_BOOT'
LEGACY_BIOS_PENALTY_ID = 'LEGACY_BIOS'
SECURE_BOOT_NOT_ENABLED_PENALTY_ID = 'SECURE_BOOT_NOT_ENABLED'
OS_OUTDATED_FOR_FONT_BLOCKING_PENALTY_ID = 'OS_OUTDATED_FOR_FONT_BLOCKING'
FONT_BLOCKING_NOT_CONFIGURED_PENALTY_ID = 'FONT_BLOCKING_NOT_CONFIGURED'
FONT_BLOCKING_IS_DISABLED_PENALTY_ID = 'FONT_BLOCKING_IS_DISABLED'
FONT_BLOCKING_MO_IS_DISABLED_PENALTY_ID = 'FONT_BLOCKING_MO_IS_DISABLED'
OS_OUTDATED_FOR_DEP_PENALTY_ID = 'OS_OUTDATED_FOR_DEP'
HW_OUTDATED_FOR_DEP_PENALTY_ID = 'HW_OUTDATED_FOR_DEP'
DEP_DISABLED_PENALTY_ID = 'DEP_DISABLED'
DEP_DISABLED32_PENALTY_ID = 'DEP_DISABLED32'
DEP_TOO_LOW_PENALTY_ID = 'DEP_TOO_LOW'
DEP_TOO_LOW32_PENALTY_ID = 'DEP_TOO_LOW32'
DEP_OVERRIDDEN_FOR_APP_PENALTY_ID = 'DEP_OVERRIDDEN_FOR_APP'
APP_NOT_OPTED_IN_FOR_DEP_PENALTY_ID = 'APP_NOT_OPTED_IN_FOR_DEP'
APP_OPTED_OUT_FROM_DEP_PENALTY_ID = 'APP_OPTED_OUT_FROM_DEP'
OS_OUTDATED_FOR_ASLR_PENALTY_ID = 'OS_OUTDATED_FOR_ASLR'
ASLR_IMPLEMENTATON_WEAK_PENALTY_ID = 'ASLR_IMPLEMENTATON_WEAK'
OS_OUTDATED_FOR_MANDATORY_ASLR_PENALTY_ID = 'OS_OUTDATED_FOR_MANDATORY_ASLR'
ASLR_CONFIG_NOT_DEFINED_PENALTY_ID = 'ASLR_CONFIG_NOT_DEFINED'
ASLR_DISABLED_PENALTY_ID = 'ASLR_DISABLED'
ASLR_CONFIG_WEAK_PENALTY_ID = 'ASLR_CONFIG_WEAK'
APP_DOES_NOT_SUPPORT_ASLR_PENALTY_ID = 'APP_DOES_NOT_SUPPORT_ASLR'
OS_OUTDATED_FOR_SEHOP_PENALTY_ID = 'OS_OUTDATED_FOR_SEHOP'
SEHOP_IS_DISABLED_PENALTY_ID = 'SEHOP_IS_DISABLED'
SEHOP_NOT_PRESENT_PENALTY_ID = 'SEHOP_NOT_PRESENT'
SEHOP_NOT_CONFIGURED_PENALTY_ID = 'SEHOP_NOT_CONFIGURED'
SEHOP_IS_DISABLED_WIN8_PENALTY_ID = 'SEHOP_IS_DISABLED_WIN8'
APP_DOES_NOT_SUPPORT_SEHOP_PENALTY_ID = 'APP_DOES_NOT_SUPPORT_SEHOP'
SEHOP_OVERRIDDEN_FOR_APP_PENALTY_ID = 'SEHOP_OVERRIDDEN_FOR_APP'
OS_OUTDATED_FOR_KSEHOP_PENALTY_ID = 'OS_OUTDATED_FOR_KSEHOP'
KSEHOP_NOT_CONFIGURED_PENALTY_ID = 'KSEHOP_NOT_CONFIGURED'
KSEHOP_IS_DISABLED_PENALTY_ID = 'KSEHOP_IS_DISABLED'
OS_OUTDATED_FOR_NULL_PAGE_PROTECTION_PENALTY_ID = 'OS_OUTDATED_FOR_NULL_PAGE_PROTECTION'
ABLE_TO_MAP_NULL_PAGE_PENALTY_ID = 'ABLE_TO_MAP_NULL_PAGE'
NP_NOT_CONFIGURED_PENALTY_ID = 'NP_NOT_CONFIGURED'
NP_IS_DISABLED_PENALTY_ID = 'NP_IS_DISABLED'
NP_NOT_PRESENT_PENALTY_ID = 'NP_NOT_PRESENT'
OS_OUTDATED_FOR_CFG_PENALTY_ID = 'OS_OUTDATED_FOR_CFG'
CFG_NOT_PRESENT_PENALTY_ID = 'CFG_NOT_PRESENT'
CFG_DISABLED_FOR_OS_PENALTY_ID = 'CFG_DISABLED_FOR_OS'
CFG_DISABLED_MO_FOR_OS_PENALTY_ID = 'CFG_DISABLED_MO_FOR_OS'
CERTPADDING_NOT_PRESENT_PENALTY_ID = 'CERTPADDING_NOT_PRESENT'
CERTPADDING_NOT_EXIST_PENALTY_ID = 'CERTPADDING_NOT_EXIST'
CERTPADDING_NOT_ENABLED_PENALTY_ID = 'CERTPADDING_NOT_ENABLED'
OS_OUTDATED_FOR_SECURE_SEARCH_PATH_PENALTY_ID = 'OS_OUTDATED_FOR_SECURE_SEARCH_PATH'
SSP_NOT_PRESENT_PENALTY_ID = 'SSP_NOT_PRESENT'
SSP_NOT_EXIST_PENALTY_ID = 'SSP_NOT_EXIST'
SSP_NOT_ENABLED_PENALTY_ID = 'SSP_NOT_ENABLED'


def get_penalty_ids():
    """
    Get the list of penalty IDs used by the analyzer.
    """
    return [HW_NO_SMEP_PENALTY_ID, HW_NO_SMAP_PENALTY_ID, OS_NO_SMEP_PENALTY_ID, OS_NO_SMAP_PENALTY_ID, OS_OUTDATED_FOR_FONT_BLOCKING_PENALTY_ID, FONT_BLOCKING_NOT_CONFIGURED_PENALTY_ID,
            FONT_BLOCKING_IS_DISABLED_PENALTY_ID, FONT_BLOCKING_MO_IS_DISABLED_PENALTY_ID, OS_OUTDATED_FOR_DEP_PENALTY_ID, HW_OUTDATED_FOR_DEP_PENALTY_ID, DEP_DISABLED_PENALTY_ID,
            DEP_DISABLED32_PENALTY_ID, DEP_TOO_LOW_PENALTY_ID, DEP_TOO_LOW32_PENALTY_ID, DEP_OVERRIDDEN_FOR_APP_PENALTY_ID, APP_NOT_OPTED_IN_FOR_DEP_PENALTY_ID, APP_OPTED_OUT_FROM_DEP_PENALTY_ID,
            OS_OUTDATED_FOR_ASLR_PENALTY_ID, ASLR_IMPLEMENTATON_WEAK_PENALTY_ID, OS_OUTDATED_FOR_MANDATORY_ASLR_PENALTY_ID, ASLR_CONFIG_NOT_DEFINED_PENALTY_ID, ASLR_DISABLED_PENALTY_ID,
            ASLR_CONFIG_WEAK_PENALTY_ID, APP_DOES_NOT_SUPPORT_ASLR_PENALTY_ID, OS_OUTDATED_FOR_SEHOP_PENALTY_ID, SEHOP_IS_DISABLED_PENALTY_ID, SEHOP_NOT_PRESENT_PENALTY_ID,
            SEHOP_NOT_CONFIGURED_PENALTY_ID, SEHOP_IS_DISABLED_WIN8_PENALTY_ID, APP_DOES_NOT_SUPPORT_SEHOP_PENALTY_ID, SEHOP_OVERRIDDEN_FOR_APP_PENALTY_ID, OS_OUTDATED_FOR_KSEHOP_PENALTY_ID,
            KSEHOP_NOT_CONFIGURED_PENALTY_ID, KSEHOP_IS_DISABLED_PENALTY_ID, OS_OUTDATED_FOR_NULL_PAGE_PROTECTION_PENALTY_ID, ABLE_TO_MAP_NULL_PAGE_PENALTY_ID, NP_NOT_CONFIGURED_PENALTY_ID,
            NP_IS_DISABLED_PENALTY_ID, NP_NOT_PRESENT_PENALTY_ID, OS_OUTDATED_FOR_CFG_PENALTY_ID, CFG_NOT_PRESENT_PENALTY_ID, CFG_DISABLED_FOR_OS_PENALTY_ID, CFG_DISABLED_MO_FOR_OS_PENALTY_ID,
            CERTPADDING_NOT_PRESENT_PENALTY_ID, CERTPADDING_NOT_EXIST_PENALTY_ID, CERTPADDING_NOT_ENABLED_PENALTY_ID, OS_OUTDATED_FOR_SECURE_SEARCH_PATH_PENALTY_ID, SSP_NOT_PRESENT_PENALTY_ID,
            SSP_NOT_EXIST_PENALTY_ID, SSP_NOT_ENABLED_PENALTY_ID]

MO_CFG_OFFSET = 40
MO_CFG_DISABLED = (2**MO_CFG_OFFSET) * 2
MO_CFG_ENABLED = (2**MO_CFG_OFFSET) * 1
CFG_DISABLED = 0
CFG_ENABLED = 1


def get_cfg_name(value):
    """
    Translate a Control Flow Guard value to a friendly name.
    """

    return {
        CFG_DISABLED: 'Disabled',
        CFG_ENABLED: 'Enabled',
        }.get(value, 'Unknown')


MO_UNTRUSTED_FONT_OFFSET = 48
MO_UNTRUSTED_FONT_BLOCK = (2**MO_UNTRUSTED_FONT_OFFSET) * 1
MO_UNTRUSTED_FONT_ALLOW = (2**MO_UNTRUSTED_FONT_OFFSET) * 2
MO_UNTRUSTED_FONT_AUDIT = (2**MO_UNTRUSTED_FONT_OFFSET) * 3
UNTRUSTED_FONT_BLOCK = 1
UNTRUSTED_FONT_ALLOW = 2
UNTRUSTED_FONT_AUDIT = 3


def get_untrusted_font_policy_name(value):
    """
    Translate a font blocking value to a friendly name.
    """

    return {
        UNTRUSTED_FONT_BLOCK: 'Block untrusted fonts and log events',
        UNTRUSTED_FONT_ALLOW: 'Do not block untrusted fonts',
        UNTRUSTED_FONT_AUDIT: 'Log events without blocking untrusted fonts'
        }.get(value, 'Unknown')


DEP_DEFER = 0
DEP_ALWAYS_ON = 1
DEP_ALWAYS_OFF = 2
DEP_ALWAYS_ON_THUNK = 3


def get_dep_policy_name(value):
    """
    Translate a DEP value to a friendly name.
    """

    return {
        DEP_DEFER: 'Defer',
        DEP_ALWAYS_ON: 'Always On',
        DEP_ALWAYS_OFF: 'Always Off',
        DEP_ALWAYS_ON_THUNK: 'Always On with thunk emulation'
        }.get(value, 'Unknown')


MOVE_IMAGES_ALWAYS_ON = -1
MOVE_IMAGES_ALWAYS_OFF = 0
MOVE_IMAGES_OPT_IN = 1


def get_moveimages_name(value):
    """
    Translate a MoveImages value to a friendly name.
    """

    return {
        MOVE_IMAGES_ALWAYS_ON: 'Always On',
        MOVE_IMAGES_ALWAYS_OFF: 'Always Off',
        MOVE_IMAGES_OPT_IN: 'Opt In'  # if MoveImages doesn't exist, then it is the same as OptIn. Applies to Vista/7 only.
        }.get(value, 'Unknown')


DECV_ENABLED = 0
DECV_DISABLED = 1


def get_decv_name(value):
    """
    Translate a DisableExceptionChainValidation value to a friendly name.
    """

    return {
        DECV_ENABLED: 'Enabled',  # enabled by default in Windows Server 2008/Windows Server 2008 R2
        DECV_DISABLED: 'Disabled'  # disabled by default in Vista/Windows 7
        }.get(value, 'Unknown')


KSEHOP_ENABLED = 1
KSEHOP_DISABLED = 0


def get_ksehop_name(value):
    """
    Translate a KernelSEHOPEnabled value to a friendly name.
    """

    return {
        KSEHOP_DISABLED: 'Disabled',  # enabled by default on Windows 8.1+ x64
        KSEHOP_ENABLED: 'Enabled'  # disabled by default on Windows 8.1+ x86
        }.get(value, 'Unknown')


NULL_PAGE_ENABLED = 0
NULL_PAGE_DISABLED = 1


def get_null_page_name(value):
    """
    Translate a EnableLowVaAccess value to a friendly name.
    """

    return {
        NULL_PAGE_ENABLED: 'Enabled',  # enabled by default with patch on Vista/Windows 7 x64, automatically only Windows 8+ x86/x64
        NULL_PAGE_DISABLED: 'Disabled'  # disabled by default with patch on Vista/Windows 7 x86
        }.get(value, 'Unknown')


CERT_PADDING_ENABLED = 1
CERT_PADDING_DISABLED = 0


def get_cert_padding_name(value):
    """
    Translate a EnableCertPaddingCheck value to a friendly name.
    """

    return {
        CERT_PADDING_DISABLED: 'Disabled',
        CERT_PADDING_ENABLED: 'Enabled'
        }.get(value, 'Unknown')


SSP_REMOVE = -1
SSP_DEFAULT = 0
SSP_BLOCK_WEBDAV = 1
SSP_BLOCK_WEBDAV_UNC = 2


def get_search_path_name(value):
    """
    Translate a CWDIllegalInDLLSearch value to a friendly name.
    """

    return {
        SSP_REMOVE: 'Remove current working directory from DLL search order',
        SSP_DEFAULT: 'Use default DLL search order',
        SSP_BLOCK_WEBDAV: 'Block DLL load from current working directory if it is a WebDAV path',
        SSP_BLOCK_WEBDAV_UNC: 'Block DLL load from current working directory if it is a WebDAV or UNC path'
        }.get(value, 'Unknown')

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


def is_int(value, base=10):
    """
    Tests if a value can be converted to an integer.
    """

    isint = False

    try:
        int(value, base)
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


def get_hotfixes(root):
    """
    Get hotfixes as a list.
    """

    found_hotfixes = []

    if root is not None and root.__class__ is ET.Element:
        hotfixes_element = root.find(HOTFIXES_ELEMENT)

        if hotfixes_element is not None:
            for hotfix in hotfixes_element.iter(HOTFIX_ELEMENT):
                hotfix_text = get_element_text(hotfix)

                if hotfix_text != '':
                    if hotfix_text not in found_hotfixes:
                        found_hotfixes.append(hotfix_text)

    return found_hotfixes


def score_hardware(system, root, penalties):
    """Scores a system based on the presence of certain hardware security features"""

    applied_penalties = []

    hardware_element = root.find(HW_SUPPORT_ELEMENT)

    if hardware_element is not None:
        smep_element = hardware_element.find(SMEP_ELEMENT)
        smap_element = hardware_element.find(SMAP_ELEMENT)

        if smep_element is not None:
            if not get_element_text(smep_element).lower() == 'yes':
                applied_penalties.append(penalties[HW_NO_SMEP_PENALTY_ID])

        if smap_element is not None:
            if not get_element_text(smap_element).lower() == 'yes':
                applied_penalties.append(penalties[HW_NO_SMAP_PENALTY_ID])

    if system.os_version < 6.2:
        applied_penalties.append(penalties[OS_NO_SMEP_PENALTY_ID])

    if system.os_version < 6.3:
        applied_penalties.append(penalties[OS_NO_SMAP_PENALTY_ID])

    return applied_penalties


def score_uefi_secure_boot(system, root, penalties):
    """Scores a system based on whether or not it supports UEFI Secure Boot"""

    applied_penalties = []

    if system.os_version < 6.2:
        applied_penalties.append(penalties[OS_NO_SECURE_BOOT_PENALTY_ID])
    else:
        system_mitigations_element = root.find(SYS_MITS_ELEMENT)

        if system_mitigations_element is not None:
            firmware_element = system_mitigations_element.find(FIRMWARE_TYPE_ELEMENT)
            secure_boot_element = system_mitigations_element.find(SECURE_BOOT_ELEMENT)

            firmware_text = get_element_text(firmware_element).lower()
            secure_boot_text = get_element_text(secure_boot_element).lower()

            if firmware_text == 'legacy':
                applied_penalties.append(penalties[LEGACY_BIOS_PENALTY_ID])
            elif firmware_text == 'uefi':
                if secure_boot_text == 'no':
                    applied_penalties.append(penalties[SECURE_BOOT_NOT_ENABLED_PENALTY_ID])
            elif firmware_text == 'unknown':
                log.error('did not retrieve system firmware type')

    return applied_penalties


def score_font_blocking(system, root, penalties):
    """Scores a system based on whether or not it supports untrusted font blocking"""

    applied_penalties = []

    if system.os_version < 10:
        applied_penalties.append(penalties[OS_OUTDATED_FOR_FONT_BLOCKING_PENALTY_ID])
    else:
        system_mitigations_element = root.find(SYS_MITS_ELEMENT)

        if system_mitigations_element is not None:
            font_block_element = system_mitigations_element.find(FONT_BLOCKING_ELEMENT)

            if font_block_element is None:
                applied_penalties.append(penalties[FONT_BLOCKING_NOT_CONFIGURED_PENALTY_ID])
            else:
                font_blocking_text = get_element_text(font_block_element)

                if is_int(font_blocking_text):
                    font_blocking_value = int(font_blocking_text)

                    if font_blocking_value != UNTRUSTED_FONT_BLOCK:
                        penalty = copy.deepcopy(penalties[FONT_BLOCKING_IS_DISABLED_PENALTY_ID])
                        penalty.reason = penalty.reason.format(font_blocking_value, get_untrusted_font_policy_name(font_blocking_value), UNTRUSTED_FONT_BLOCK, get_untrusted_font_policy_name(UNTRUSTED_FONT_BLOCK))
                        applied_penalties.append(penalty)

            mo_element = root.find(MIT_OPTS_ELEMENT)

            if mo_element is not None:
                mo_text = get_element_text(mo_element)

                if is_int(mo_text, 16):
                    mo_value = int(mo_text, 16)

                    if (mo_value >= MO_UNTRUSTED_FONT_BLOCK) and (mo_value & MO_UNTRUSTED_FONT_BLOCK != MO_UNTRUSTED_FONT_BLOCK):
                        flag = int(('{0:2X}'.format(mo_value >> MO_UNTRUSTED_FONT_OFFSET))[-1])
                        # mo_cleared = mo_value & ~( (2**MO_UNTRUSTED_FONT_OFFSET) * flag)
                        mo_cleared = mo_value & ~(1 << MO_UNTRUSTED_FONT_OFFSET)
                        mo_enabled = mo_cleared | MO_UNTRUSTED_FONT_BLOCK

                        penalty = copy.deepcopy(penalties[FONT_BLOCKING_MO_IS_DISABLED_PENALTY_ID])
                        penalty.reason = penalty.reason.format(mo_value, mo_enabled, flag, get_untrusted_font_policy_name(flag))
                        applied_penalties.append(penalty)

    return applied_penalties


def score_dep(system, root, penalties):
    """
    Scores the DEP configuration both of the system and of a select set
    of applications examined by the associated LOCKLEVEL plugin. This list
    is based on the set of applications addressed by EMET.
    """

    applied_penalties = []

    # Verify the OS is new enough to support DEP
    # At least XP SP2 or Server 2003 SP1

    do_penalty = False

    if system.os_version < 5.1:
        do_penalty = True
    elif system.os_version == 5.1 and not system.is_server and system.os_service_pack < 2:
        do_penalty = True
    elif system.os_version == 5.2 and not system.is_server and system.os_service_pack < 2:
        do_penalty = True
    elif system.os_version == 5.2 and system.is_server and system.os_service_pack < 1:
        do_penalty = True

    if do_penalty:
        applied_penalties.append(penalties[OS_OUTDATED_FOR_DEP_PENALTY_ID])
        return applied_penalties

    supports_pae = False
    supports_dep = False

    hardware_element = root.find(HW_SUPPORT_ELEMENT)

    if hardware_element is not None:
        pae_element = hardware_element.find(PAE_ELEMENT)
        nx_element = hardware_element.find(NX_ELEMENT)

        if pae_element is not None:
            if get_element_text(pae_element).lower() == 'yes':
                supports_pae = True

        if nx_element is not None:
            if get_element_text(nx_element).lower() == 'yes':
                supports_dep = True

    if not (supports_dep and (system.is64bit or supports_pae)):
        applied_penalties.append(penalties[HW_OUTDATED_FOR_DEP_PENALTY_ID])
        return applied_penalties

    # Verify system configured to support DEP. For 64-bit systems DEP is ALWAYS ON for 64-bit
    # apps and is in fact impossible to turn off. For 32-bit apps it is possible to configure
    # whether DEP is on in various ways.
    #
    # Note that the boot configuration DEP setting is
    # is overridden by the system MitigationOptions setting, which in turn is overridden by
    # the IFEO MitigationOptions setting, unless the former has the policy override bit, in
    # which case it overrides the IFEO MitigationOptions setting

    dep_boot_policy = DEP_ALWAYS_ON_TEXT.lower()
    mitigation_options = 0
    mo_dep_policy = 0
    mo_dep_policy_override = 0

    # MitigationOptions DEP policy
    #    0 defer to higher level setting
    #    1 always on
    #    2 always off
    #    3 always on with thunk emulation

    system_mitigations_element = root.find(SYS_MITS_ELEMENT)

    if system_mitigations_element is not None:
        dep_policy_element = system_mitigations_element.find(DEP_POLICY_ELEMENT)

        if dep_policy_element is not None:
            dep_boot_policy = get_element_text(dep_policy_element)

        mitigation_options_element = system_mitigations_element.find(MIT_OPTS_ELEMENT)

        if mitigation_options_element is not None and is_int(get_element_text(mitigation_options_element), 16):
            mitigation_options = int(get_element_text(mitigation_options_element), 16)
            mo_dep_policy = mitigation_options & 0x3

            # If policy override is set, the mitigation policy overrides settings under
            # the Image File Execution Options (IFEO) key

            mo_dep_policy_override = (mitigation_options & 4) >> 2

    if mo_dep_policy == 2 or (mo_dep_policy == 0 and dep_boot_policy.lower() == DEP_ALWAYS_OFF_TEXT.lower()):
        if not system.is64bit:
            applied_penalties.append(penalties[DEP_DISABLED_PENALTY_ID])
        else:
            applied_penalties.append(penalties[DEP_DISABLED32_PENALTY_ID])

        return applied_penalties
    elif mo_dep_policy == 0 and (dep_boot_policy.lower() == DEP_OPT_IN_TEXT.lower() or dep_boot_policy.lower() == DEP_OPT_OUT_TEXT.lower()):
        if not system.is64bit:
            applied_penalties.append(penalties[DEP_TOO_LOW_PENALTY_ID])
        else:
            applied_penalties.append(penalties[DEP_TOO_LOW32_PENALTY_ID])

    # If policy override bit is set, we don't need to check app level settings, since
    # they are overridden

    if mo_dep_policy_override:
        return applied_penalties

    # Now check to see whether DEP is applied for the apps we care about.
	
	# todo some apps are not compiled with DEP, but opt-in at runtime via API, so we need to eliminate those false positives
	# todo known false positives are wmplayer.exe and iexplore.exe

    app_mitigations_element = root.find(APP_MITS_ELEMENT)

    if app_mitigations_element is None:
        return applied_penalties

    for app in app_mitigations_element:
        app_name = app.get(PATH_ATTRIBUTE)

        if app_name is None:
            continue

        # 64-bit apps always have DEP
        machine_element = app.find(MACHINE_ATTRIBUTE)

        if machine_element is not None and is_int(get_element_text(machine_element)):
            machine = int(get_element_text(machine_element))

            if machine == IMAGE_FILE_MACHINE_IA64 or machine == IMAGE_FILE_MACHINE_AMD64:
                continue

        # Check to see whether DEP for apps we care about is disabled at
        # the IFEO level.

        app_mo_dep_policy = 0
        mitigation_options_element = app.find(MIT_OPTS_ELEMENT)

        if mitigation_options_element is not None and is_int(get_element_text(mitigation_options_element), 16):
            app_mo_dep_policy = 0x3 & int(get_element_text(mitigation_options_element), 16)

            if app_mo_dep_policy == 2:
                penalty = copy.deepcopy(penalties[DEP_OVERRIDDEN_FOR_APP_PENALTY_ID])
                penalty.reason = penalty.reason.format(app_name)
                applied_penalties.append(penalty)

        # If there is a mitigation_options configuration we don't need to
        # check the legacy configurations

        if mo_dep_policy != 0 or app_mo_dep_policy != 0:
            continue

        # Otherwise if the boot DEP configuration is always on, no additional
        # configurations can override that.

        if dep_boot_policy.lower() == DEP_ALWAYS_ON_TEXT.lower():
            continue

        # If boot configuration is OptIn, verify the app is opted in.

        if dep_boot_policy.lower() == DEP_OPT_IN_TEXT.lower():
            nxcompat = False
            dllchar_element = app.find(DLLCHARACTERISTICS_ELEMENT)

            if dllchar_element is not None and is_int(get_element_text(dllchar_element)):
                dllchar = int(get_element_text(dllchar_element))
                nxcompat = (dllchar & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0

            execute_options = False
            execute_options_element = app.find(EXEC_OPTS_ELEMENT)

            if execute_options_element is not None and is_int(get_element_text(execute_options_element), 16):
                execute_options = (int(get_element_text(execute_options_element), 16) == 0)

            if not nxcompat and not execute_options:
                penalty = copy.deepcopy(penalties[APP_NOT_OPTED_IN_FOR_DEP_PENALTY_ID])
                penalty.reason = penalty.reason.format(app_name)
                applied_penalties.append(penalty)

        # If the boot configuration is opt_out, verify the app is not opted out

        elif dep_boot_policy.lower() == DEP_OPT_OUT_TEXT:
            opt_out = False
            app_compat_element = app.find(APP_COMPAT_ELEMENT)

            if app_compat_element is not None and get_element_text(app_compat_element) != '':
                app_compat_text = get_element_text(app_compat_element)

                if app_compat_text.lower() == DEP_APPCOMPAT_DISABLE_HIDE_TEXT or app_compat_text.lower() == DEP_APPCOMPAT_DISABLE_SHOW_TEXT:
                    opt_out = True

            if opt_out:
                penalty = copy.deepcopy(penalties[APP_OPTED_OUT_FROM_DEP_PENALTY_ID])
                penalty.reason = penalty.reason.format(app_name)
                applied_penalties.append(penalty)

    return applied_penalties


def score_aslr(system, root, penalties):
    """
    Scores the ASLR configuration both of the system and of a select set
    of applications examined by the associated LOCKLEVEL plugin. This list
    is based on the set of applications addressed by EMET.
    """

    applied_penalties = []

    # If the OS is 8 or later, ASLR may not be disabled. In tests on Windows 2012 and Windows 8.1,
    # set MitigationOptions to 0x200 (ASLR off) and MoveImages to 0 and rebooted. ASLR still applied
    # to both 32-bit and 64-bit apps.

    if system.os_version >= 6.2:
        return applied_penalties

    # Verify the OS is new enough to support ASLR

    do_penalty = False

    if system.os_version < 5.1:
        do_penalty = True
    elif system.os_version == 5.1 and not system.is_server and system.os_service_pack < 2:
        do_penalty = True
    elif system.os_version == 5.2 and not system.is_server and system.os_service_pack < 2:
        do_penalty = True
    elif system.os_version == 5.2 and system.is_server and system.os_service_pack < 1:
        do_penalty = True

    # todo check these assumptions. though OS ALSR started in Vista. these look like app ASLR via EMET checks

    if do_penalty:
        applied_penalties.append(penalties[OS_OUTDATED_FOR_ASLR_PENALTY_ID])
        return applied_penalties

    # If OS is 32 bit (and version is earlier than Windows 8), then ALSR implementation is
    # known to be weak.

    if not system.is64bit:
        applied_penalties.append(penalties[ASLR_IMPLEMENTATON_WEAK_PENALTY_ID])

    # Verify mandatory ALSR on operating system prior to 6.2 via moveimages value

    move_images = 0

    system_mitigations_element = root.find(SYS_MITS_ELEMENT)

    if system_mitigations_element is not None:
        move_images_element = system_mitigations_element.find(MOVE_IMAGES_ELEMENT)

        if move_images_element is not None:
            if is_int(get_element_text(move_images_element), 16):
                move_images = int(get_element_text(move_images_element), 16)

    if system.os_version < 6.0:
        applied_penalties.append(penalties[OS_OUTDATED_FOR_MANDATORY_ASLR_PENALTY_ID])
    else:

        # Note that if there is no MoveImages registry value the OS defaults to Optin
        if move_images_element is None:
            applied_penalties.append(penalties[ASLR_CONFIG_NOT_DEFINED_PENALTY_ID])
        else:
            if move_images == 0:
                applied_penalties.append(penalties[ASLR_DISABLED_PENALTY_ID])
                return applied_penalties
            elif move_images == 1:
                applied_penalties.append(penalties[ASLR_CONFIG_WEAK_PENALTY_ID])

    # TODO if system.osVersion >= 6.2 then check MitigationOptions?

    # Now check to see whether ALSR is applied for the apps we care about.

    app_mitigations_element = root.find(APP_MITS_ELEMENT)

    if app_mitigations_element is None:
        return applied_penalties

    for app in app_mitigations_element:
        app_name = app.get(PATH_ATTRIBUTE)

        if app_name is None:
            continue

        supports_aslr = False
        dllchar_element = app.find(DLLCHARACTERISTICS_ELEMENT)

        if dllchar_element is not None and is_int(get_element_text(dllchar_element)):
            dllchar = is_int(get_element_text(dllchar_element))
            supports_aslr = (dllchar & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0

        if not supports_aslr:
            applied_penalties.append(penalties[APP_DOES_NOT_SUPPORT_ASLR_PENALTY_ID])

    return applied_penalties


def score_sehop(system, root, penalties):
    """
    Scores the Structured Exception Handling Overwrite Protection
    configuration both of the system and of a select set of applications
    examined by the associated LOCKLEVEL plugin. This list is based on
    the set of applications addressed by EMET.
    """

    applied_penalties = []

    # Verify the OS is new enough to support SEHOP

    if system.os_version < 6.0 or (system.os_version == 6.0 and system.os_service_pack == 0):
        applied_penalties.append(penalties[OS_OUTDATED_FOR_SEHOP_PENALTY_ID])
        return applied_penalties

    # Check the decv for older OSes and check MitigationsOptions on newer OSes

    system_mitigations_element = root.find(SYS_MITS_ELEMENT)
    mo_sehop_policy = 0
    #  moSEHOPOverrideBit = 0

    if system_mitigations_element is None:
        return applied_penalties

    if system.os_version < 6.2:
        decv = -1
        decv_element = system_mitigations_element.find(DECV_ELEMENT)

        if decv_element is not None:
            if is_int(get_element_text(decv_element), 16):
                decv = int(get_element_text(decv_element), 16)

        if decv != 0:
            applied_penalties.append(penalties[SEHOP_IS_DISABLED_PENALTY_ID])
    else:
        mitigations_options_element = system_mitigations_element.find(MIT_OPTS_ELEMENT)

        if mitigations_options_element is None:
            applied_penalties.append(penalties[SEHOP_NOT_PRESENT_PENALTY_ID])
        else:
            if is_int(get_element_text(mitigations_options_element), 16):
                mo_sehop_policy = 0x3 & (int(get_element_text(mitigations_options_element), 16) >> 4)
                #  moSEHOPOverrideBit = 0x1 & (int(get_element_text(mitigations_options_element)) >> 6)

                if mo_sehop_policy == 0:
                    applied_penalties.append(penalties[SEHOP_NOT_CONFIGURED_PENALTY_ID])
                elif mo_sehop_policy == 2:
                    applied_penalties.append(penalties[SEHOP_IS_DISABLED_WIN8_PENALTY_ID])

    # Now check the apps and make sure they are enabled for SEHOP

    app_mitigations_element = root.find(APP_MITS_ELEMENT)

    if app_mitigations_element is None:
        return applied_penalties

    for app in app_mitigations_element:
        app_name = app.get(PATH_ATTRIBUTE)

        if app_name is None:
            continue

        if system.os_version < 6.2:
            app_decv = app.find(DECV_ELEMENT)
            supports_sehop = True

            if app_decv is not None and app_decv.text != '0x00000000':
                supports_sehop = False

            if not supports_sehop:
                penalty = copy.deepcopy(penalties[APP_DOES_NOT_SUPPORT_SEHOP_PENALTY_ID])
                penalty.reason = penalty.reason.format(app_name)
                applied_penalties.append(penalty)
        else:
            # Check to see whether SEHOP for apps we care about is disabled at the IFEO level.
            app_mo_sehop_policy = 0
            app_mo_element = app.find(MIT_OPTS_ELEMENT)

            if app_mo_element is not None:
                if is_int(get_element_text(app_mo_element), 16):
                    app_mo_sehop_policy = 0x3 & (int(get_element_text(app_mo_element), 16) >> 4)

                    if app_mo_sehop_policy != 1:
                        penalty = copy.deepcopy(penalties[SEHOP_OVERRIDDEN_FOR_APP_PENALTY_ID])
                        penalty.reason = penalty.reason.format(app_name)
                        applied_penalties.append(penalty)

    return applied_penalties


def score_kernel_sehop(system, root, penalties):
    """
    Scores the kernel Structured Exception Handling Overwrite Protection for the OS.
    """

    applied_penalties = []

    # Verify the OS is new enough to support kernel SEHOP
    # Only Windows 8.1+

    if system.os_version < 6.3:
        applied_penalties.append(penalties[OS_OUTDATED_FOR_KSEHOP_PENALTY_ID])
        return applied_penalties

    system_mitigations_element = root.find(SYS_MITS_ELEMENT)

    # x64 has kernel SEHOP so only need to check x86
    if not system.is64bit:
        if system_mitigations_element is not None:
            kernel_sehop_element = system_mitigations_element.find(KSEHOP_ELEMENT)

            if kernel_sehop_element is not None:
                ksehop_text = get_element_text(kernel_sehop_element)

                if is_int(ksehop_text):
                    ksehop_value = int(ksehop_text)

                    if ksehop_value != KSEHOP_ENABLED:
                        penalty = penalties[KSEHOP_IS_DISABLED_PENALTY_ID]
                        penalty.reason = penalty.reason.format(ksehop_value, get_ksehop_name(ksehop_value), KSEHOP_ENABLED, get_ksehop_name(KSEHOP_ENABLED))
            else:
                applied_penalties.append(penalties[KSEHOP_NOT_CONFIGURED_PENALTY_ID])

    return applied_penalties


def score_kernel_null_page(system, root, penalties):
    """
    Scores system as to whether it blocks mapping of the Null page, a mitigation
    that can prevent kernel Null pointer dereference exploits.
    """

    applied_penalties = []

    # todo Vista might support this with the right patch, need to investigate
    if system.os_version < 6.1:
        applied_penalties.append(penalties[OS_OUTDATED_FOR_NULL_PAGE_PROTECTION_PENALTY_ID])
        return applied_penalties

    map_null_page = 'no'

    system_mitigations_element = root.find(SYS_MITS_ELEMENT)

    if system_mitigations_element is not None:
        null_page_element = system_mitigations_element.find(NULL_PAGE_ELEMENT)

        if null_page_element is not None:
            map_null_page = get_element_text(null_page_element)

    # todo what about when == ''
    if map_null_page.lower() == 'yes':
        applied_penalties.append(penalties[ABLE_TO_MAP_NULL_PAGE_PENALTY_ID])

        null_page_hotfixes = ['KB3035131', 'KB3045999', 'KB3000483', 'KB3031432', 'KB3023266', 'KB2839229', 'KB2859537', 'KB2872339', 'KB2829361', 'KB3033395', 'KB2813170']
        found_hotfixes = []
        null_page_supported = False

        # todo Vista might support this with the right patch, need to investigate
        if system.os_version == 6.1:
            found_hotfixes = get_hotfixes(root)

            if len(found_hotfixes) > 0:
                if len(set(null_page_hotfixes).intersection(set(found_hotfixes))) > 0:
                    null_page_supported = True

            if null_page_supported:
                null_access_element = system_mitigations_element.find(LOW_VA_ELEMENT)

                if null_access_element is not None:
                    null_access_text = get_element_text(null_access_element)

                    if is_int(null_access_text):
                        null_access_value = int(null_access_text)

                        if null_access_value != NULL_PAGE_ENABLED:
                            penalty = copy.deepcopy(penalties[NP_NOT_CONFIGURED_PENALTY_ID])
                            penalty.reason = penalty.reason.format(null_access_value, get_null_page_name(null_access_value), NULL_PAGE_ENABLED, get_null_page_name(NULL_PAGE_ENABLED))
                            applied_penalties.append(penalty)
                else:
                    applied_penalties.append(penalties[NP_NOT_CONFIGURED_PENALTY_ID])
            else:
                penalty = copy.deepcopy(penalties[NP_NOT_PRESENT_PENALTY_ID])
                penalty.reason = penalty.reason.format(', '.join(null_page_hotfixes))
                applied_penalties.append(penalty)

    return applied_penalties

# TODO This requires more work and experimentation to determine what impact the
# mitigation_options and EnableCfg registry values have on whether CFG is enabled.
# In particular, we need to know what the default state of the system is.
# test with 0x10000111311 for mitigation_options


def score_control_flow_guard(system, root, penalties):
    """
    Scores a system as to whether it support Control Flow Guard and
    whether this has been applied.
    """

    applied_penalties = []

    if system.os_version < 6.3:
        applied_penalties.append(penalties[OS_OUTDATED_FOR_CFG_PENALTY_ID])
        return applied_penalties

    os_cfg_supported = False

    if system.os_version == 6.3:
        cfg_hotfixes = ['KB3000850']
        found_hotfixes = []

        found_hotfixes = get_hotfixes(root)

        if len(found_hotfixes) > 0:
            if len(set(cfg_hotfixes).intersection(set(found_hotfixes))) > 0:
                os_cfg_supported = True
            else:
                penalty = copy.deepcopy(penalties[CFG_NOT_PRESENT_PENALTY_ID])
                penalty.reason = penalty.reason.format(', '.join(cfg_hotfixes))
                applied_penalties.append(penalty)
    elif system.os_version >= 10.0:
        os_cfg_supported = True

    if os_cfg_supported:
        system_mitigations_element = root.find(SYS_MITS_ELEMENT)

        if system_mitigations_element is not None:
            cfg = root.find(CFG_ELEMENT)

            if cfg is not None:
                cfg_text = get_element_text(cfg)

                if is_int(cfg_text):
                    cfg_value = int(cfg_text)

                    if cfg_value != CFG_ENABLED:
                        penalty = copy.deepcopy(penalties[CFG_DISABLED_FOR_OS_PENALTY_ID])
                        penalty.reason = penalty.reason.format(cfg_value, get_cfg_name(cfg_value), CFG_ENABLED, get_cfg_name(CFG_ENABLED))
                        applied_penalties.append(penalty)

            mo_element = root.find(MIT_OPTS_ELEMENT)

            if mo_element is not None:
                mo_text = get_element_text(mo_element)

                if is_int(mo_text, 16):
                    mo_value = int(mo_text, 16)

                    if (mo_value >= MO_CFG_ENABLED) and (mo_value & MO_CFG_ENABLED != MO_CFG_ENABLED):
                        cfg_flag = int(('{0:2X}'.format(mo_value >> MO_CFG_OFFSET))[-1])
                        # mo_cleared = mo_value & ~( (2**MO_CFG_OFFSET) * cfg_flag)
                        mo_cleared = mo_value & ~(1 << MO_CFG_OFFSET)
                        mo_enabled = mo_cleared | MO_CFG_ENABLED

                        penalty = copy.deepcopy(penalties[CFG_DISABLED_MO_FOR_OS_PENALTY_ID])
                        penalty.reason = penalty.reason.format(mo_value, mo_enabled, cfg_flag, get_cfg_name(cfg_flag))
                        penalty.remediation = penalty.remediation.format(mo_enabled)
                        applied_penalties.append(penalty)

    # todo add support via IFEO MitigationOptions - it can only be enabled, disable is ignored

    # todo add app support via DLL characteristics?

    return applied_penalties


def score_certificate_padding(system, root, penalties):
    """
    Scores a system as to whether it support Certificate Padding and
    whether this has been applied.
    """

    applied_penalties = []
    cp_hotfix_applied = False
    padding_hotfixes = ['KB2919355', 'KB2893294']
    found_hotfixes = get_hotfixes(root)

    if len(found_hotfixes) > 0:
        if len(set(padding_hotfixes).intersection(set(found_hotfixes))) > 0:
            cp_hotfix_applied = True

    if not cp_hotfix_applied:
        penalty = copy.deepcopy(penalties[CERTPADDING_NOT_PRESENT_PENALTY_ID])
        penalty.reason = penalty.reason.format(', '.join(padding_hotfixes))
        applied_penalties.append(penalty)
        return applied_penalties

    system_mitigations_element = root.find(SYS_MITS_ELEMENT)

    if system_mitigations_element is not None:
        ecpc_element = system_mitigations_element.find(CERT_PADDING_ELEMENT)

        if ecpc_element is None:
            penalty = copy.deepcopy(penalties[CERTPADDING_NOT_EXIST_PENALTY_ID])
            penalty.reason = penalty.reason.format(WINTRUST_CONFIG_32)
            applied_penalties.append(penalty)
        else:
            cp_text = get_element_text(ecpc_element)

            if is_int(cp_text):
                cp_value = int(cp_text)

                if cp_value != CERT_PADDING_ENABLED:
                    penalty = copy.deepcopy(penalties[CERTPADDING_NOT_ENABLED_PENALTY_ID])
                    penalty.reason = penalty.reason.format(WINTRUST_CONFIG_32, cp_value, get_cert_padding_name(cp_value), CERT_PADDING_ENABLED, get_cert_padding_name(CERT_PADDING_ENABLED))
                    applied_penalties.append(penalty)

        # 64-bit OS needs the value set in the 64-bit registry path in addition to the 32-bit path
        if system.is64bit:
            ecpc_wow64_element = system_mitigations_element.find(CERT_PADDING_ELEMENT64)

            if ecpc_wow64_element is None:
                penalty = copy.deepcopy(penalties[CERTPADDING_NOT_EXIST_PENALTY_ID])
                penalty.reason = penalty.reason.format(WINTRUST_CONFIG_64)
                applied_penalties.append(penalty)
            else:
                cp_text = get_element_text(ecpc_wow64_element)

                if is_int(cp_text):
                    cp_value = int(cp_text)

                    if cp_value != CERT_PADDING_ENABLED:
                        penalty = copy.deepcopy(penalties[CERTPADDING_NOT_ENABLED_PENALTY_ID])
                        penalty.reason = penalty.reason.format(WINTRUST_CONFIG_64, cp_value, get_cert_padding_name(cp_value), CERT_PADDING_ENABLED, get_cert_padding_name(CERT_PADDING_ENABLED))
                        applied_penalties.append(penalty)

    return applied_penalties


def score_secure_search_path(system, root, penalties):
    """
    Scores a system as to whether it support Secure Search Path and
    whether this has been applied.
    """

    applied_penalties = []

    # skip the the rest of the checks since the OS is too old to support secure search paths, even with a patch
    if (system.os_version < 5.1) or (system.os_version == 5.1 and system.os_service_pack < 3):
        applied_penalties.append(penalties[OS_OUTDATED_FOR_SECURE_SEARCH_PATH_PENALTY_ID])
        return applied_penalties

    ssp_hotfix_applied = False
    search_hotfixes = ['KB2859537', 'KB3045999', 'KB2264107']
    found_hotfixes = []

    # if OS is Windows 8+, CWDllIlegalInDllSearch is supported by default but not configured.
    # earlier OSes need hotfixes installed
    if system.os_version < 6.2:
        found_hotfixes = get_hotfixes(root)

        if len(found_hotfixes) > 0:
            if len(set(search_hotfixes).intersection(set(found_hotfixes))) > 0:
                ssp_hotfix_applied = True

        if not ssp_hotfix_applied:
            penalty = copy.deepcopy(penalties[SSP_NOT_PRESENT_PENALTY_ID])
            penalty.reason = penalty.reason.format(', '.join(search_hotfixes))
            applied_penalties.append(penalty)
            return applied_penalties

    system_mitigations_element = root.find(SYS_MITS_ELEMENT)

    if system_mitigations_element is not None:
        ssp_element = system_mitigations_element.find(SECURE_SEARCH_ELEMENT)

        if ssp_element is None:
            applied_penalties.append(penalties[SSP_NOT_EXIST_PENALTY_ID])
        else:
            ssp_text = get_element_text(ssp_element)

            if is_int(ssp_text):
                ssp_value = int(ssp_text)

                if ssp_value != SSP_BLOCK_WEBDAV_UNC:
                    penalty = copy.deepcopy(penalties[SSP_NOT_ENABLED_PENALTY_ID])
                    penalty.reason = penalty.reason.format(ssp_value, get_search_path_name(ssp_value), SSP_BLOCK_WEBDAV_UNC, get_search_path_name(SSP_BLOCK_WEBDAV_UNC))
                    applied_penalties.append(penalties[penalty])

    return applied_penalties


def get_applied_penalties(path, systempath, penalties):
    """
    Get all penalties that apply to the collected information.
    """

    applied_penalties = []
    ae_tree = None
    sysinfo_tree = None
    sysinfo = None

    try:
        ae_tree = ET.parse(path)
    except Exception as error:
        log.exception('Unable to load %s due to an error of %s', systempath, error)

    # todo remove this because it is duplicative
    try:
        sysinfo_tree = ET.parse(systempath)
    except Exception as error:
        log.exception('Unable to load %s due to an error of %s', systempath, error)

    if ae_tree is not None and sysinfo_tree is not None:
        # since find/findall aren't case insensitive and XPath support is limited, force all element and attribute names to lower case
        ae_tree = lower_tree(ae_tree)
        sysinfo_tree = lower_tree(sysinfo_tree)

        ae_root = ae_tree.getroot()
        sysinfo_element = sysinfo_tree.getroot()

        sysinfo = SystemInformation(sysinfo_element)

        if ae_root is not None and ae_root.tag == AE_ELEMENT:
            applied_penalties.extend(score_hardware(sysinfo, ae_root, penalties))
            applied_penalties.extend(score_uefi_secure_boot(sysinfo, ae_root, penalties))
            applied_penalties.extend(score_font_blocking(sysinfo, ae_root, penalties))
            applied_penalties.extend(score_dep(sysinfo, ae_root, penalties))
            applied_penalties.extend(score_aslr(sysinfo, ae_root, penalties))
            applied_penalties.extend(score_sehop(sysinfo, ae_root, penalties))
            applied_penalties.extend(score_kernel_sehop(sysinfo, ae_root, penalties))
            applied_penalties.extend(score_kernel_null_page(sysinfo, ae_root, penalties))
            applied_penalties.extend(score_control_flow_guard(sysinfo, ae_root, penalties))
            applied_penalties.extend(score_certificate_padding(sysinfo, ae_root, penalties))
            applied_penalties.extend(score_secure_search_path(sysinfo, ae_root, penalties))
        else:
            log.exception("Invalid root element for %s", path)

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

        ae_xml_path = os.path.join(extract_path, AE_XML_FILE)
        system_xml_path = os.path.join(extract_path, SYSTEM_XML_FILE)

        if os.path.exists(ae_xml_path) and os.path.exists(system_xml_path):
            try:
                applied_penalties = get_applied_penalties(ae_xml_path, system_xml_path, penalty_definitions)

                write_score_xml('.'.join([extract_path, 'xml']), applied_penalties, system_xml_path, AE_VALUE)
            except Exception as error:
                log.exception('Unexpected error %s while processing system', error)
        else:
            if not os.path.exists(ae_xml_path):
                log.error('%s did not exist', ae_xml_path)

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

    parser = argparse.ArgumentParser(description='Executes the LOCKLEVEL Anti-Exploitation analyzer')
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

if __name__ == '__main__':
    main()
