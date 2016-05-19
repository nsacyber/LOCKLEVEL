"""
Scoremaster takes all the output from the mitigation analyzers and creates a JSON file that is used by the presentation layer
"""
import os
import xml.etree.ElementTree as ET
import sys
from copy import deepcopy
import argparse
import json


# XML Strings
CUMULATIVE_SCORE = 'cumulativeScore'
SYSINFO = 'systemInfo'
SCORE = 'score'
PENALTY = 'penalty'
ID = 'id'
REMEDIATION = 'remediation'
MITIGATION = 'mitigation'
NAME = 'name'


def get_sysinfo(root):
    """ Get the systeminfo element or returns None """

    sysinfo = {}
    for child in root.find(SYSINFO):
        sysinfo[child.tag] = child.text
    return sysinfo if sysinfo != {} else None


def to_dict(element):
    """ Get an element's child elements as a dictionary of attribute names mapped to values and element names mapped to text values"""

    attributes = deepcopy(element.attrib) or {}
    attributes['text'] = element.text.strip()
    for child_element in element:
        child_attributes = to_dict(child_element)
        if attributes.get(child_element.tag):
            if isinstance(attributes[child_element.tag], list):
                attributes[child_element.tag].append(child_attributes)
            else:
                attributes[child_element.tag] = [deepcopy(attributes[child_element.tag]), child_attributes]
        else:
            attributes[child_element.tag] = child_attributes
    return attributes


def get_penalties(root):
    """ Get all the penalties from the element and return a dictionary where the penalty ID is the key and the penalties are a list """

    penalties = {}
    score_element = root.find(SCORE)  # TODO not used, but ask if this is supposed to be used to check if score element's cumulativeScore is 10 first
    penalty_elements = score_element.findall(PENALTY)
    for penalty_element in penalty_elements:
        penalty = to_dict(penalty_element)
        if penalties.get(penalty[ID]):
            penalties[penalty[ID]].append(penalty)
        else:
            penalties[penalty[ID]] = [penalty]
    return penalties


def flatten_penalties(penalties):
    """ Flatten a penalty dictionary into a list """

    return [penalty for sublist in penalties.values() for penalty in sublist]


def system_hostname(system):
    """ Get a system's host name from the system info """

    return system['sysinfo']['hostName']


def merge_systems(json_data):
    """ Merge system data """

    systems = {}
    for data in json_data:
        system = systems.get(system_hostname(data),
                             {'sysinfo': data['sysinfo'], 'plugins': {}})
        system['plugins'].update(data['plugins'])
        systems[system_hostname(system)] = system
    return systems


def calculate_score(penalties):
    """ Score a list of penalties multiplicatively """

    if not isinstance(penalties, list):
        penalties = flatten_penalties(penalties)
    if len(penalties) == 0:
        return 10.0
    cumulative = 9
    for penalty in penalties:
        value = float(penalty.get('value'))
        current_score = 100 - value
        cumulative = cumulative * current_score / 100.0
    cumulative += 1
    return round(cumulative, 1)


def has_remediation(rid, penalty):
    """ Test if a penalty contains a remediation with the given remediation ID"""

    remediations = penalty['remediation']
    if isinstance(remediations, list):
        for rem in remediations:
            if rem['id'] == rid:
                return True
    else:
        if remediations['id'] == rid:
            return True
    return False


def get_remediations(system):
    """ Get the remediations for a system """

    remediations = {}
    for plugin in system['plugins'].values():
        for penalty in flatten_penalties(plugin['penalties']):
            if isinstance(penalty['remediation'], list):
                for rem in penalty['remediation']:
                    remediations[rem['id']] = True
            else:
                remediations[penalty['remediation']['id']] = True
    return remediations.keys()


def filter_remediation(rid, penalties):
    """ Get the remediations from the penalties based on the remediation ID """

    penalties = flatten_penalties(penalties)
    return filter(lambda p: not has_remediation(rid, p), penalties)


def calculate_plugin_score(plugin, remediation=None):
    """ Calculate the score for the plugin based on if remediation is applied """
    if remediation:
        return calculate_score(filter_remediation(remediation, plugin['penalties']))
    return calculate_score(plugin['penalties'])


def calculate_system_score(system, remediation=None):
    """ Calculate the score for the system based on if remediation is applied """

    score = []
    # TODO weight scores based on plugin weights
    for plugin in system['plugins'].values():
        score.append(calculate_plugin_score(plugin, remediation))
    return round(sum(score) / len(score), 1)


def calculate_network_score(network, remediation=None):
    """ Calculate the network score based on if remediation is applied """

    score = []
    network_score = 0.0

    for system in network.values():
        scores = system.get('scores')
        score.append(scores.get('remediations', {}).get(remediation) or scores.get('base'))

    if len(score) > 0:
        network_score = round(sum(score) / len(score), 1)

    return network_score


def calculate_overall_plugin_scores(systems):
    """ Calculate overall score for each mitigation plugin across all systems """

    # TODO this function could be made much more efficient

    final_scores = {}
    temp_scores = {}

    for system in systems.itervalues():
        for name, score in system['scores']['plugins'].iteritems():
            if name in temp_scores:
                temp_scores[name].append(score)
            else:
                temp_scores[name] = [score]

    for name in temp_scores.iterkeys():
        if len(temp_scores[name]) > 0:
            final_scores[name] = round((sum(temp_scores[name])/len(temp_scores[name])), 1)
        else:
            final_scores[name] = 1.0

    return final_scores


def get_overall_scores(systems):
    """ Get overall scores include the total overall score and then overall score for each plugin """

    overall = {}

    overall_plugin_scores = calculate_overall_plugin_scores(systems)

    overall['base'] = 1.0

    if len(overall_plugin_scores.items()) > 0:
        overall['base'] = round(sum(overall_plugin_scores.itervalues()) / len(overall_plugin_scores.items()), 1)

    overall['plugins'] = overall_plugin_scores

    return overall


def jsonify(tree):
    """ Turn an XML tree into JSON """

    mitigation = tree.getroot()
    plugin = mitigation.attrib.get(NAME)
    sysinfo = get_sysinfo(mitigation)
    penalties = get_penalties(mitigation)

    return {
        'sysinfo': sysinfo,
        'plugins': {
            plugin: {
                'score': calculate_score(penalties),
                'penalties': penalties
            }
        }
    }


def main():
    """ Main scoremaster logic"""

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", dest='inputdir', help='Input directory containing XML files from analyzers.', required=True)
    parser.add_argument("-o", dest='outputdir', help='Output directory for the resulting json output.', required=True)
    parser.add_argument("-f", dest='format', action="store_true", help='Optionally format the score.json output for easier reading.', required=False)

    args = parser.parse_args()

    if not os.path.exists(args.inputdir):
        sys.exit('Input path of {0} does not exist'.format(args.inputdir))

    if not os.path.isdir(args.inputdir):
        sys.exit('Input path of {0} is not a directory'.format(args.inputdir))

    if not os.path.exists(args.outputdir):
        sys.exit('Output path of {0} does not exist'.format(args.outputdir))

    if not os.path.isdir(args.outputdir):
        sys.exit('Output path of {0} is not a directory'.format(args.outputdir))

    inputdir = args.inputdir
    outputdir = args.outputdir
    pretty = args.format

    xml = []

    for root, dirs, files in os.walk(inputdir):
        for input_file in files:
            if input_file.endswith('.xml'):
                tree = ET.parse(os.path.join(root, input_file))
                if tree.getroot().tag == 'mitigation':
                    xml.append(tree)

    json_data = [jsonify(x) for x in xml]

    systems = merge_systems(json_data)

    remediations = {None: True}

    for system in systems.values():
        scores = {'remediations': {}, 'plugins': {}}
        scores['base'] = calculate_system_score(system)

        for plugin in system['plugins'].keys():
            scores['plugins'][plugin] = system['plugins'][plugin]['score']

        for remediation in get_remediations(system):
            remediations[remediation] = True
            scores['remediations'][remediation] = calculate_system_score(system, remediation)

        system['scores'] = scores

    overall_scores = get_overall_scores(systems)

    remediation_scores = {}

    for remediation in remediations.keys():
        remediation_scores[remediation] = calculate_network_score(systems, remediation)

    indent = 4 if pretty else None

    with open(os.path.join(outputdir, 'score.json'), 'w') as json_file:
        json.dump({'systems': systems, 'remediation_scores': remediation_scores, 'scores': overall_scores}, json_file, ensure_ascii=True, indent=indent, separators=(',', ':'))

	# TODO remove directory workaround once GUI is fixed
    presentation_dir = os.path.join(outputdir, '../../presentation/code/')
    # the presentation layer expects a score.js file that has the JSON data assigned to the scoreData variable
    with open(os.path.join(presentation_dir, 'score.js'), 'w') as js_file:
        js_file.write('var scoreData = ')
        json.dump({'systems': systems, 'remediation_scores': remediation_scores, 'scores': overall_scores}, js_file, ensure_ascii=True, indent=indent, separators=(', ', ': '))

    return

if __name__ == "__main__":
    main()
