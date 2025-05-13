'''
CapsLock is a tool that helps you analyze the capabilities of a package in Golang. 
- https://github.com/google/capslock/tree/main

This is a tool to diff two different scans of the same package for capability changes around Capslock.

Given two different scans, we should be able to find the differences between them.
The capabilities are mostly serious things so there are not many false positives.
- https://github.com/google/capslock/blob/c9355aa2f9687c73c507b4edcaaec6ed929d9a03/proto/capability.proto#L89

Format:
- PackageName:
    - The name of the package where the dependency is located.
- Capability: 
    - The capability of the package. List is above of the possible ones. 
- Path:
    - A list of the path to the dependency. 
    - Goes from the root of the package to the dependency.
    - Items:
        - Name - Function name
        - Package - Package name
        - Site - Location of the actual code that this has affected.
- depPath:
    - The list of the path to the dependency.
    - A string with spaces between the packages being used.

Capabilities explained: 
- ARBITRARY_EXECUTION: usage of ``go:linkname`` directive. 
- CAPABILITY_CGO: usage of C or Asm 
- CAPABILITY_SYSTEM_CALLS: Make direct system calls.
- CAPABILITY_OPERATING_SYSTEM: os package that are not explicitly categorized. 
- CAPABILITY_FILES: Reading or writing to the file system.
- CAPABILITY_READ_SYSTEM_STATE/CAPABILITY_MODIFY_SYSTEM_STATE: Reading or writing to the system state, such as environment variables, process information, etc. 
- CAPABILITY_NETWORK: Make network calls.
- CAPABILITY_ARBITRARY_EXECUTION/CAPABILITY_UNSAFE_POINTER: Ability to violate Go safety rules, such as the `unsafe` package.
- CAPABILITY_EXEC: Execute a command on the system via the `os/exec` package.

https://github.com/google/capslock/blob/c9355aa2f9687c73c507b4edcaaec6ed929d9a03/docs/capabilities.md
'''

import json 
import argparse
import sys  # Add this import at the top
import requests 
import time 
import os
import git

# Add this function near the end of the file, before the current execution code
def parse_arguments():
    """
    Parse command line arguments for package name and capability files.
    """
    parser = argparse.ArgumentParser(description='Compare two CapsLock capability scans for differences.')
    parser.add_argument('--package', '-p', type=str, 
                        help='The package name to analyze (e.g., "example.com/includee")')
    parser.add_argument('--old', '-o', type=str, 
                        help='Path to the old capability JSON file')
    parser.add_argument('--new', '-n', type=str, 
                        help='Path to the new capability JSON file')
    parser.add_argument('--standalone', '-s', type=bool, help= 'Path to the standalone capability JSON file')
    parser.add_argument('--webhook_url', '-w', type=str, help= 'Webhook URL for Slack notifications. Used for Slack integration')
    parser.add_argument('--commit_hash', '-hash', type=str, help= 'Commit hash for the commit to compare against. Used for Slack integration.')
    parser.add_argument('--repo_url', '-ru', type=str, help= 'Repo URL for the commit to compare against. Used for Slack integration.')
    parser.add_argument('--output', '-ou', type=str, help= 'Output file location. Defaults to no file.')

    return parser.parse_args()


def get_repo_root():
    """Get the absolute path to the repository root."""
    try:
        repo = git.Repo(os.path.dirname(os.path.abspath(__file__)), search_parent_directories=True)
        return repo.git.rev_parse("--show-toplevel")
    except git.InvalidGitRepositoryError:
        # Fallback if not in a git repo
        return os.path.dirname(os.path.abspath(__file__))
    
def get_capability_danger_levels():
    """
    Returns a dictionary mapping capability types to danger levels (1-10).
    Higher numbers indicate more dangerous capabilities.
    """
    return {
        "CAPABILITY_ARBITRARY_EXECUTION": 10,  # Highest risk - can execute arbitrary code
        "CAPABILITY_UNSAFE_POINTER": 9,        # Can violate Go safety rules
        "CAPABILITY_EXEC": 9,                  # Can execute system commands
        "CAPABILITY_SYSTEM_CALLS": 8,          # Direct system calls
        "CAPABILITY_MODIFY_SYSTEM_STATE": 4,   # Can modify system state
        "CAPABILITY_FILES": 7,                 # File system access
        "CAPABILITY_NETWORK": 6,               # Network access
        "CAPABILITY_CGO": 8,                   # Usage of C or Assembly
        "CAPABILITY_OPERATING_SYSTEM": 4,      # General OS package usage
        "CAPABILITY_READ_SYSTEM_STATE": 3,      # Reading system state (less dangerous than modifying)
        "CAPABILITY_RUNTIME" : 9, 
        "CAPABILITY_UNANALYZED" : 3, 
        "CAPABILITY_REFLECT" : 7
    }

def read_cap_file(path):
    with open(path, 'r') as file:
        data = json.load(file)
        return data['capabilityInfo']

def format_cap_file(data, current):
    entry_dict = {}
    overall_entries = {}
    for entry in data:
        paths = entry['path']
        capability = entry['capability']
        depPath = entry['depPath']
        cap_type = entry['capabilityType']

        # Means that it was included in the package directly. 
        # This needs to be reviewed in a PR so it's acceptable to skip.
        if(cap_type == "CAPABILITY_TYPE_DIRECT"):
            continue

        shallow_path = "" # Find out where this is coming from.
        for path in paths: 
            if(current not in path['package']):
                shallow_path = path['package']
                break
        name = shallow_path
        
        # If done by our own package, then we don't care about it.
        if(shallow_path == ""):
            continue 

        item = {"capability" : capability, "module" : shallow_path, "full_path" : paths, "depPath" : depPath}

        if(name not in entry_dict):
            entry_dict[shallow_path] = [item]
        else:
            entry_dict[shallow_path].append(item)
        
        if(capability not in overall_entries):
            overall_entries[capability] = 1
        else:
            overall_entries[capability] += 1
    return entry_dict, overall_entries


def diff_capability_scans(old_scan, new_scan):
    """
    Compare two capability scans and identify new capabilities in the new scan.
    
    Args:
        old_scan (dict): The old capability scan data
        new_scan (dict): The new capability scan data
        
    Returns:
        dict: A dictionary containing only the new capabilities found
    """
    new_capabilities = {}
    
    # Iterate through packages in the new scan
    for package_name, capabilities in new_scan.items():
        # Check if this package exists in the old scan
        if package_name in old_scan:
            # Package exists in both scans, need to check for new capabilities
            old_capabilities = old_scan[package_name]
            
            # Find capabilities in new scan that weren't in old scan
            new_package_capabilities = []
            
            for new_cap in capabilities:
                # Check if this capability was present in the old scan
                is_new = True
                for old_cap in old_capabilities:
                    # Compare capability type
                    if new_cap['capability'] == old_cap['capability']:
                        # Compare depPath to ensure it's the same path
                        if new_cap['depPath'] == old_cap['depPath']:
                            is_new = False
                            break
                if is_new:
                    new_package_capabilities.append(new_cap)
            
            # If we found new capabilities for this package, add them to our result
            if new_package_capabilities:
                new_capabilities[package_name] = new_package_capabilities
        else:
            # This is a completely new package, include all its capabilities
            new_capabilities[package_name] = capabilities
    
    return new_capabilities

def print_capability_diff(diff_result):
    """
    Print a human-readable summary of the capability differences.
    
    Args:
        diff_result (dict): The result from diff_capability_scans
    """
    danger_levels = get_capability_danger_levels()
    
    output = []
    
    for package_name, capabilities in diff_result.items():
        output.append(f"Package: {package_name}")
        output.append("-" * 50)
        
        # Sort capabilities by danger level (highest first)
        sorted_capabilities = sorted(
            capabilities, 
            key=lambda x: danger_levels.get(x['capability'], 0),
            reverse=True
        )
        
        for cap in sorted_capabilities:
            danger_level = danger_levels.get(cap['capability'], "Unknown")
            output.append(f"  • {cap['capability']} (Danger Level: {danger_level})")
            output.append(f"    Path: {cap['depPath']}")
            
            # Print the actual code location if available
            for path_item in cap['full_path']:
                if 'site' in path_item:
                    site = path_item['site']
                    output.append(f"    Location: {site.get('filename', 'unknown')}:{site.get('line', '?')}:{site.get('column', '?')}")
                    break
            
            output.append("")
        
        output.append("")
    
    # Join all lines into a single string
    result_string = "\n".join(output)
    return result_string

def capability_diff_to_string(diff_result):
    """
    Convert capability differences to a human-readable string.
    
    Args:
        diff_result (dict): The result from diff_capability_scans
        
    Returns:
        str: A formatted string representation of the capability differences
    """
    danger_levels = get_capability_danger_levels()
    output = []
    
    if not diff_result:
        return "No new capabilities detected."

    for cap in diff_result:
        danger_level = danger_levels.get(cap['capability'], "Unknown")
        output.append(f"  • {cap['capability']} (Danger Level: {danger_level})")
        output.append(f"    Path: {cap['depPath']}")
        
        # Print the actual code location if available
        for path_item in cap['full_path']:
            if 'site' in path_item:
                site = path_item['site']
                output.append(f"    Location: {site.get('filename', 'unknown')}:{site.get('line', '?')}:{site.get('column', '?')}")
                break
        
        output.append("")
    return "\n".join(output)

'''
Push to slack using the folling format:
-----------------------------------------------
New Capability - <CAPABILITY_NAME>

Type: CAPABILITY_NAME           Commit: <COMMIT_HASH>
Danger Level: <DANGER_LEVEL>    Package Name: <PACKAGE_NAME>

Path: <PATH_TO_CAPABILITY>
Location: <FILE_NAME>:<LINE_NUMBER>:<COLUMN_NUMBER>
'''
def send_slack_webhook(webhook_ulr, data, commit_hash, repo_url):

    if(webhook_ulr == ""):
        webhook_url = "" # Used for testing...
        return 
    else:
        webhook_url = webhook_ulr

    if(commit_hash == "" or repo_url == ""):
        commit_content = "N/A"
    else: 
        commit_content = f"<{repo_url}/commit/{commit_hash}|{commit_hash[0:12]}>"

    # Define the webhook URL
    danger_levels = get_capability_danger_levels()
    for package in data:
        for violations in data[package]:
            capability = violations['capability']
            depPath = violations['depPath']
            danger_level = danger_levels.get(violations['capability'], "Unknown")

            site_data = None 
            for path_item in violations['full_path']:
                if 'site' in path_item:
                    site = path_item['site']
                    site_data = f"{site.get('filename', 'unknown')}:{site.get('line', '?')}"
                    break

            path = "\n".join(depPath.split(' '))
            if site_data:
                path += f"\nCalling Location: {site_data}"

            # Styling on slack 
            # https://api.slack.com/block-kit/building
            body = {
            
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"Wormhole Capability Change",
                                "emoji": True
                            }
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Type:*\n<https://github.com/google/capslock/blob/main/docs/capabilities.md#{capability}|{capability}>"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Danger Level:*\n {danger_level}/10"
                                },
                            ]
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Package:*\n`<https://pkg.go.dev/{package}|{package}>`",
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Commit Scanned:*\n{commit_content}"
                                }
                            ]
                        },
                        {
                            "type": "section",
                            "text": 
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Path*\n ```\n{path}\n```" # Make each package its own line to make it easier to read
                                }
                        },
                        {
                            "type": "section",
                            "text": {
                                "type" : "mrkdwn", 
                                "text" : f"If you need more information, read through <https://github.com/google/capslock|Capslock> and <https://github.com/asymmetric-research/capslock_automation|Capslock Automation>."
                            }
                        }
                    ]
            }

            headers = {
                "Content-Type": "application/json"
            }
            print(f"Sending webhook request for package: {package}")
            result = requests.post(
                webhook_url,
                headers=headers,
                json=body
            )
            print(result.text)

            time.sleep(5) 
    
if __name__ == "__main__":
    args = parse_arguments()
    
    # Use command line arguments if provided, otherwise use defaults

    # Test values.
    my_package = args.package if args.package else "github.com/certusone/wormhole/node"
    old_file_path = args.old if args.old else './packages_for_test/test_package2/cap2.json'
    new_file_path = args.new if args.new else './packages_for_test/test_package2/cap1.json'  # Default to same file if not specified

    # Read and format capability files
    old_data = read_cap_file(old_file_path)
    old_dep_information, old_overall_entries = format_cap_file(old_data, my_package)
    
    if(args.standalone == True):
        # Just print the single scan information
        print(f"Analyzing capabilities for package: {my_package}")
        
        cap_string = print_capability_diff(old_dep_information)
        print(cap_string)
        # Output the results to a file if specified
        if(args.output != ""):
            if(args.output == "default"):
                # Write the output to a file
                output_path = os.path.join(get_repo_root(), "node", ".capabilities.txt")
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
            else:
                output_path = args.output
            with open(output_path, 'w') as f:
                f.write(cap_string)

        sys.exit(0) 

    # If different file specified for new scan, process it
    new_data = read_cap_file(new_file_path)
    new_dep_information, new_overall_entries = format_cap_file(new_data, my_package)
    
    # Compare the scans
    diff = diff_capability_scans(old_dep_information, new_dep_information)
    diff_string = print_capability_diff(diff)
    print("=== NEW CAPABILITIES DETECTED ===\n")
    print(diff_string)

    # If using CI, publish the results to Slack
    if(args.webhook_url != ""):
        commit_hash = args.commit_hash if args.commit_hash else ""
        webhook_url = args.webhook_url if args.webhook_url else ""
        repo_url = args.repo_url if args.repo_url else ""
        send_slack_webhook(webhook_url, diff, commit_hash, repo_url)

