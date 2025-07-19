# FortiGate IPsec VPN Config Parser

A Python script to parse and correlate IPsec VPN tunnel data from raw FortiGate config files.

## Features

- Parses phase1 and phase2 VPN interfaces
- Resolves address groups to actual subnets
- Correlates and outputs source/destination subnet mappings
- Prints results in a table and saves structured output to `output.txt`

## Requirements

- Python 3.7+
- `rich` library (`pip install rich`)

## Usage

```bash
python fg_vpn_parser.py <path_to_config.txt>
```
