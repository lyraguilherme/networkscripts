import re
import sys
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown


def parse_phase1_interface_block(config):
    result_dict = {}
    in_section = False
    current_entry = None

    lines = config.splitlines()

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("config vpn ipsec phase1-interface"):
            in_section = True
            continue

        if in_section:
            if stripped.startswith("edit "):
                current_entry = stripped.split('"')[1]
                result_dict[current_entry] = {}

            elif stripped.startswith("set ") and current_entry:
                parts = stripped.split(maxsplit=2)
                if len(parts) >= 3:
                    key = parts[1]
                    value = parts[2].strip()
                    result_dict[current_entry][key] = value
                elif len(parts) == 2:
                    key = parts[1]
                    result_dict[current_entry][key] = True  # flag-style option

            elif stripped == "next":
                current_entry = None

            elif stripped == "end":
                break

    return result_dict


def parse_phase2_interface_block(config):

    result_dict = {}
    in_section = False
    current_entry = None
    lines = config.splitlines()

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("config vpn ipsec phase2-interface"):
            in_section = True
            continue

        if in_section:

            if stripped.startswith("edit "):
                current_entry = stripped.split('"')[1]
                result_dict[current_entry] = {}

            elif stripped.startswith("set ") and current_entry:
                parts = stripped.split(maxsplit=2)
                if len(parts) == 3:
                    _, key, value = parts
                    result_dict[current_entry][key] = value.strip('"')

            elif stripped == "next":
                current_entry = None

            elif stripped == "end":
                break

    return result_dict


def parse_firewall_addrgrp_block(config):
    result_dict = {}
    in_section = False
    current_entry = None
    collecting_members = False
    member_lines = []

    lines = config.splitlines()

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("config firewall addrgrp"):
            in_section = True
            continue

        if in_section:
            if stripped.startswith("edit "):
                current_entry = stripped.split('"')[1]
                result_dict[current_entry] = {}
                member_lines = []
                collecting_members = False

            elif stripped.startswith("set ") and current_entry:
                parts = stripped.split(maxsplit=2)
                if len(parts) < 3:
                    continue

                key = parts[1]
                value = parts[2]

                if key == "member":
                    collecting_members = True
                    member_lines = [value]
                else:
                    result_dict[current_entry][key] = value.strip('"')

            elif collecting_members and not stripped.startswith("set ") and stripped not in {"next", "end"}:
                member_lines.append(stripped)

            elif stripped == "next":
                if collecting_members:
                    joined = " ".join(member_lines)
                    members = re.findall(r'"(.*?)"', joined)
                    result_dict[current_entry]["member"] = members
                    collecting_members = False
                current_entry = None

            elif stripped == "end":
                break

    return result_dict


def parse_firewall_address_block(config):
    result_dict = {}
    in_section = False
    current_entry = None

    lines = config.splitlines()

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("config firewall address"):
            in_section = True
            continue

        if in_section:
            if stripped.startswith("edit "):
                current_entry = stripped.split('"')[1]
                result_dict[current_entry] = {}

            elif stripped.startswith("set ") and current_entry:
                parts = stripped.split(maxsplit=2)
                if len(parts) >= 3:
                    key = parts[1]
                    value = parts[2].strip()
                    result_dict[current_entry][key] = value
                elif len(parts) == 2:
                    key = parts[1]
                    result_dict[current_entry][key] = True  # flag-style value

            elif stripped == "next":
                current_entry = None

            elif stripped == "end":
                break

    return result_dict


def correlate(phase1_result, phase2_result, addrgrp_result, address_result):
    correlated = {}

    # First pass: from phase1
    for tunnel_name, p1_data in phase1_result.items():
        correlated[tunnel_name] = {}
        for key in ["remote-gw", "proposal", "dhgrp", "nattraversal"]:
            if key in p1_data:
                correlated[tunnel_name][key] = p1_data[key]

    # Second pass: from phase2
    for tunnel_name, p2_data in phase2_result.items():
        if tunnel_name not in correlated:
            correlated[tunnel_name] = {}

        for key in ["phase1name", "pfs", "keylifeseconds", "src-name", "dst-name"]:
            if key in p2_data:
                correlated[tunnel_name][key] = p2_data[key]

    # Third pass: src-name/dst-name → addrgrp → member
    for tunnel_name, entry in correlated.items():
        for direction in ["src-name", "dst-name"]:
            name_key = entry.get(direction)
            if name_key and name_key in addrgrp_result:
                members = addrgrp_result[name_key].get("member")
                if isinstance(members, list):
                    entry[f"{direction}-list"] = members

    # Fourth pass: resolve members to subnets from address_result
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


def print_correlated_data(correlated_dict):
    console = Console()

    for vpn_key, vpn_data in correlated_dict.items():
        table = Table(title=f"[bold]{vpn_key}[/bold]", show_lines=True)
        table.add_column("Field", style="cyan bold", no_wrap=True)
        table.add_column("Value", style="white")

        for k, v in vpn_data.items():
            if isinstance(v, list):
                table.add_row(k, "\n".join(v) if v else "-")
            else:
                table.add_row(k, v if v else "-")

        console.print(Panel(table, border_style="green"))


def write_correlated_data_to_file(data, filename="output.txt"):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(json.dumps(data, indent=4))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <config_file>")
        sys.exit(1)

    config_file_path = sys.argv[1]

    with open(config_file_path, "r") as f:
        config_text = f.read()

    phase1_result = parse_phase1_interface_block(config_text)
    phase2_result = parse_phase2_interface_block(config_text)
    addrgrp_result = parse_firewall_addrgrp_block(config_text)
    address_result = parse_firewall_address_block(config_text)
    correlated_data = correlate(phase1_result, phase2_result, addrgrp_result, address_result)


    # Uncomment the following lines to print the raw results

    #print("\n\nIPSec Phase 1 Interfaces:")
    #print(json.dumps(phase1_result, indent=4))

    #print("\n\nIPSec Phase 2 Interfaces:")
    #print(json.dumps(phase2_result, indent=4))

    #print("\n\nFirewall Address Groups:")
    #print(json.dumps(addrgrp_result, indent=4))

    #print("\n\nFirewall Addresses:")
    #print(json.dumps(address_result, indent=4))

    #print("\n\nCorrelated Data:")
    #print(json.dumps(correlated_data, indent=4, sort_keys=True))

    print_correlated_data(correlated_data)
    write_correlated_data_to_file(correlated_data)
