import re
import sys
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown


# Parses the Phase1 interface block and builds a dictionary of all entries
def parse_phase1_interface_block(config):
    result_dict = {}
    in_section = False
    current_entry = None
    lines = config.splitlines()

    for line in lines:
        stripped = line.strip()

        # Start parsing when the phase1 block is found
        if stripped.startswith("config vpn ipsec phase1-interface"):
            in_section = True
            continue

        if in_section:
            # New tunnel entry begins
            if stripped.startswith("edit "):
                current_entry = stripped.split('"')[1]
                result_dict[current_entry] = {}

            # Add key-value pairs under the current tunnel
            elif stripped.startswith("set ") and current_entry:
                parts = stripped.split(maxsplit=2)
                if len(parts) >= 3:
                    key = parts[1]
                    value = parts[2].strip()
                    result_dict[current_entry][key] = value
                elif len(parts) == 2:
                    key = parts[1]
                    result_dict[current_entry][key] = True

            # End of current entry
            elif stripped == "next":
                current_entry = None

            # End of section
            elif stripped == "end":
                break

    return result_dict


# Parses the Phase2 interface block and builds a dictionary of entries
def parse_phase2_interface_block(config):
    result_dict = {}
    in_section = False
    current_entry = None
    lines = config.splitlines()

    for line in lines:
        stripped = line.strip()

        # Start parsing when the phase2 block is found
        if stripped.startswith("config vpn ipsec phase2-interface"):
            in_section = True
            continue

        if in_section:
            # Start of a new phase2 tunnel entry
            if stripped.startswith("edit "):
                current_entry = stripped.split('"')[1]
                result_dict[current_entry] = {}

            # Capture key-value pairs
            elif stripped.startswith("set ") and current_entry:
                parts = stripped.split(maxsplit=2)
                if len(parts) == 3:
                    _, key, value = parts
                    result_dict[current_entry][key] = value.strip('"')

            # End of current entry
            elif stripped == "next":
                current_entry = None

            # End of section
            elif stripped == "end":
                break

    return result_dict


# Parses firewall address groups and captures their members
def parse_firewall_addrgrp_block(config):
    result_dict = {}
    in_section = False
    current_entry = None
    collecting_members = False
    member_lines = []

    lines = config.splitlines()

    for line in lines:
        stripped = line.strip()

        # Start parsing address group section
        if stripped.startswith("config firewall addrgrp"):
            in_section = True
            continue

        if in_section:
            # Start of a new group
            if stripped.startswith("edit "):
                current_entry = stripped.split('"')[1]
                result_dict[current_entry] = {}
                member_lines = []
                collecting_members = False

            # Parse fields under the current group
            elif stripped.startswith("set ") and current_entry:
                parts = stripped.split(maxsplit=2)
                if len(parts) < 3:
                    continue

                key = parts[1]
                value = parts[2]

                # Start collecting group members
                if key == "member":
                    collecting_members = True
                    member_lines = [value]
                else:
                    result_dict[current_entry][key] = value.strip('"')

            # Additional lines for member list
            elif collecting_members and not stripped.startswith("set ") and stripped not in {"next", "end"}:
                member_lines.append(stripped)

            # End of group entry
            elif stripped == "next":
                if collecting_members:
                    joined = " ".join(member_lines)
                    members = re.findall(r'"(.*?)"', joined)
                    result_dict[current_entry]["member"] = members
                    collecting_members = False
                current_entry = None

            # End of section
            elif stripped == "end":
                break

    return result_dict


# Parses firewall address objects and captures subnets or definitions
def parse_firewall_address_block(config):
    result_dict = {}
    in_section = False
    current_entry = None

    lines = config.splitlines()

    for line in lines:
        stripped = line.strip()

        # Start parsing address section
        if stripped.startswith("config firewall address"):
            in_section = True
            continue

        if in_section:
            # Start of a new address object
            if stripped.startswith("edit "):
                current_entry = stripped.split('"')[1]
                result_dict[current_entry] = {}

            # Key-value config inside address block
            elif stripped.startswith("set ") and current_entry:
                parts = stripped.split(maxsplit=2)
                if len(parts) >= 3:
                    key = parts[1]
                    value = parts[2].strip()
                    result_dict[current_entry][key] = value
                elif len(parts) == 2:
                    key = parts[1]
                    result_dict[current_entry][key] = True

            # End of current address
            elif stripped == "next":
                current_entry = None

            # End of section
            elif stripped == "end":
                break

    return result_dict


# Combines all the parsed pieces into one unified dictionary
def correlate(phase1_result, phase2_result, addrgrp_result, address_result):
    # Create a new dictionary to hold correlated data
    correlated = {}

    # Step 1: Load basic info from phase1 config
    for tunnel_name, p1_data in phase1_result.items():
        correlated[tunnel_name] = {}
        for key in ["remote-gw", "proposal", "dhgrp", "nattraversal"]:
            if key in p1_data:
                correlated[tunnel_name][key] = p1_data[key]

    # Step 2: Add matching phase2 data
    for tunnel_name, p2_data in phase2_result.items():
        if tunnel_name not in correlated:
            correlated[tunnel_name] = {}

        for key in ["phase1name", "pfs", "keylifeseconds", "src-name", "dst-name"]:
            if key in p2_data:
                correlated[tunnel_name][key] = p2_data[key]

    # Step 3: Expand src-name and dst-name into member lists
    for tunnel_name, entry in correlated.items():
        for direction in ["src-name", "dst-name"]:
            name_key = entry.get(direction)
            if name_key and name_key in addrgrp_result:
                members = addrgrp_result[name_key].get("member")
                if isinstance(members, list):
                    entry[f"{direction}-list"] = members

    # Step 4: Resolve address object names to actual subnets
    for tunnel_name, entry in correlated.items():
        for direction in ["src-name", "dst-name"]:
            member_list = entry.get(f"{direction}-list", [])
            subnet_list = []

            for name in member_list:
                addr_data = address_result.get(name)
                if addr_data and "subnet" in addr_data:
                    subnet_list.append(addr_data["subnet"])

            entry[f"extracted-{direction}-subnets"] = subnet_list

    return correlated


# Prints the correlated data as tables
def print_correlated_data(correlated_dict):
    console = Console()

    for vpn_key, vpn_data in correlated_dict.items():
        table = Table(title=f"[bold]{vpn_key}[/bold]", show_lines=True)
        table.add_column("Field", style="cyan bold", no_wrap=True)
        table.add_column("Value", style="white")

        for k, v in vpn_data.items():
            # Join list entries with newlines for readability
            if isinstance(v, list):
                table.add_row(k, "\n".join(v) if v else "-")
            else:
                table.add_row(k, v if v else "-")

        console.print(Panel(table, border_style="black"))


# Writes the full correlated data to a text file
def write_correlated_data_to_file(data, filename="output.txt"):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(json.dumps(data, indent=4))


if __name__ == "__main__":
    # Ensure a config file path is passed as argument
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <config_file>")
        sys.exit(1)

    # Read the config file from cli argument
    config_file_path = sys.argv[1]

    # Load config from file
    with open(config_file_path, "r") as f:
        config_text = f.read()

    # Run all parsing steps
    phase1_result = parse_phase1_interface_block(config_text)
    phase2_result = parse_phase2_interface_block(config_text)
    addrgrp_result = parse_firewall_addrgrp_block(config_text)
    address_result = parse_firewall_address_block(config_text)

    # Perform correlation of all parsed data
    correlated_data = correlate(phase1_result, phase2_result, addrgrp_result, address_result)

    # Optional raw dump for debugging
    # print(json.dumps(phase1_result, indent=4))
    # print(json.dumps(correlated_data, indent=4))

    # Display table summary and write structured output to file
    print_correlated_data(correlated_data)
    write_correlated_data_to_file(correlated_data)
