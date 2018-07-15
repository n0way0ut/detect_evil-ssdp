# Detect evil SSDP (https://gitlab.com/initstring/evil-ssdp) with osquery


## Overview

This repo contains a python-based extension for osquery to detect active instances of rogue SSDP server on the local network.

This extension uses native Python modules only to reduce the need for installing third-party Python libraries on hosts. 

Note: This extension has not been tested on production networks and exists only as a PoC yet.

## How it works
The extension operates by sending 1 SSDP multicast M-SEARCH request with a random service type and wait for the SSDP response.

## Installation
The osquery-python package must be installed on the system via `$ pip install --user osquery`.

Create a folder  called `/var/osquery/extensions` (MacOS) or `/etc/osquery/extensions` (Linux), `chmod 755` it, or `C:\ProgramData\osquery\extensions` (Windows) and copy the extension to that directory.

  To configure the extension to load when osquery starts, do one of the following:
* Create a file called `extensions.load` in `/var/osquery` (MacOS) or `/etc/osquery` (Linux) or `C:\ProgramData\osquery\` and populate the file with the full path to `detect_ssdp.py`
* Edit your osquery flags file and add the following flag: `--extension /path/to/extensions.load`

## Usage
Once you have verified that the extension has loaded correctly, you should be able to run `SELECT * FROM detect_ssdp;`. 
To test it, run evil-ssdp on a different host on the same network.

To test using osqueryi, run:
`sudo osqueryi --nodisable_extensions --extension /var/osquery/extensions/detect_ssdp.py --verbose`

