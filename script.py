import os
import json
import pprint
import re
import argparse
from statistics import mean
from collections import Counter


import numpy as np
import matplotlib.pyplot as plt


# Tools
sca_tools = ['Grype.txt', 'Snyk.txt', 'Trivy.txt']

# RICs
rics = ['ONOS', 'OSC']

repoWithError = []


numVuln = { # This is used to contain the needed data from all data for plotting
    'ONOS': {
        'Grype.txt': {},
        'Snyk.txt': {},
        'Trivy.txt': {}
    },
    'OSC': {
        'Grype.txt': {},
        'Snyk.txt': {},
        'Trivy.txt': {}
    },
    'OAIC': {
        'Grype.txt': {},
        'Snyk.txt': {},
        'Trivy.txt': {}
    }
}

# Packages to exclude in the RIC repos
test_package = re.compile('test/')
benchmark_package = re.compile('benchmark')
examples_package = re.compile('examples/')
testapplication_package = re.compile('testapplication/')


# First we normalize the results from each tool
def format_sca_tool_data(repository, tool):
    if tool == "Grype.txt":
        return formatGrype(repository)
    elif tool == "Snyk.txt":
        return formatSnyk(repository)
    elif tool == "Trivy.txt":
        return formatTrivy(repository)

# This gets all the vulnerabilities in a normalized way.
#(In a list which includes all the vulnerabilities, which are not contained in a test package )
def formatGrype(repository):
    GrypeRepo = json.loads(repository)
    vulnArray = []
    for vuln in GrypeRepo["matches"]:
        path = vuln.get("artifact").get("locations")[0].get("path")
        if test_package.search(path) is not None:
            print("Grype: Skipping")
            continue
        elif benchmark_package.search(path) is not None:
            print("Grype: Skipping")
            continue
        elif examples_package.search(path) is not None:
            print("Grype: Skipping")
            continue
        elif testapplication_package.search(path) is not None:
            print("Grype: Skipping")
            continue
        else:
            vulnArray.append(vuln)
    return vulnArray

def formatSnyk(repository):
    content = json.loads(repository)
    vulnArray = []
    if "error" not in content:
        for target in content:
            if not isinstance(target, str):
                # breakpoint()
                vulnList = target.get('vulnerabilities')
                path = target.get('displayTargetFile')
                if test_package.search(path) is not None:
                    print("Snyk: Skipping:" + path)
                    continue
                elif benchmark_package.search(path) is not None:
                    print("Snyk: Skipping:" + path)
                    continue
                elif examples_package.search(path) is not None:
                    print("Snyk: Skipping:" + path)
                    continue
                elif testapplication_package.search(path) is not None:
                    print("Snyk: Skipping:" + path)
                    continue
                else:
                    for vuln in vulnList:
                        vuln.pop('semver')
                        # vuln['path'] = path
                        vulnArray.append(vuln)
            else:
                if target == 'vulnerabilities':
                    vulnList = content.get('vulnerabilities')
                    path = content.get('displayTargetFile')
                    print("Snyk path: {}".format(path))
                    # breakpoint()
                    if test_package.search(path) is not None:
                        print("Snyk: Skipping:" + path)
                        continue
                    elif benchmark_package.search(path) is not None:
                        print("Snyk: Skipping:" + path)
                        continue
                    elif examples_package.search(path) is not None:
                        print("Snyk: Skipping:" + path)
                        continue
                    elif testapplication_package.search(path) is not None:
                        print("Snyk: Skipping:" + path)
                        continue
                    else:
                        for vuln in vulnList:
                            vuln.pop('semver')
                            # vuln['path']=path
                            vulnArray.append(vuln)
                            print("1")
    else:
        global repoWithError
        repoWithError.append(os.path.basename(content['path']))
    # print("Snyk vulnerabilties found: " + str(len(vulnArray)))
    return vulnArray

def formatTrivy(repository):
    index = repository.find("{")
    repo = repository[index:]
    TrivyRepo = json.loads(repo)
    results = TrivyRepo.get("Results")
    vulnArray = []
    if results is not None:
        for target in results:
            path = target.get("Target")
            # print("Trivy path:" + path)
            if test_package.search(path) is not None:
                print("Trivy: Skipping:" + path)
                continue
            elif benchmark_package.search(path) is not None:
                print("Trivy: Skipping:" + path)
                continue
            elif examples_package.search(path) is not None:
                print("Trivy: Skipping:" + path)
                continue
            else:
                vulnTarget = target.get("Vulnerabilities", [])
                # Skip if vulnTarget is an empty list
                if not vulnTarget:
                    continue
                for vuln in vulnTarget:
                    vuln["Path"] = path
                # this is an copy of each of the lists that we made and add the path manually
                vulnArray.extend(vulnTarget)
    # print("Found " + str(len(vulnArray)) + " vulnerabilities.")
    return vulnArray

def main():
    parser = argparse.ArgumentParser(description='Format SCA tool data')
    parser.add_argument('data_file', type=str, help='Path to the data file in JSON format')
    parser.add_argument('tool', type=str, choices=['Grype.txt', 'Snyk.txt', 'Trivy.txt'], help='SCA tool used')
    args = parser.parse_args()

    with open(args.data_file, 'r') as file:
        data = file.read()

    formatted_data = format_sca_tool_data(data, args.tool)
    pprint.pprint(formatted_data)
    print(len(formatted_data))

if __name__ == "__main__":
    main()