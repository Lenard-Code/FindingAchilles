# FindingAchilles
<div align="center">
  <img src="/FindingAchilles.jpg" alt="FindingAchilles Logo" />
</div>

## Description
FindingAchilles is a Python-based tool designed to identify Common Vulnerabilities and Exposures (CVEs) for specified software and versions by querying various databases and sources.

## Requirements
Python 3.x<br/>
NVD API Key<br/>
requests<br/>
beautifulsoup4<br/>
pyExploitDb<br/>
## Installation
Clone the repository:<br/>
sh<br/>
git clone https://github.com/Lenard-Code/FindingAchilles.git<br/>
cd FindingAchilles<br/>
## Install the required dependencies:
pip install -r requirements.txt
## Usage
Prepare a JSON file containing software names and versions:
JSON
[
    {"name": "software1", "version": "1.0"},
    {"name": "software2", "version": "2.1"}
]
## Run the script:
python FindingAchilles.py path/to/your/json_file.json
Example
python FindingAchilles.py software_versions.json
## Acknowledgments
This project makes use of code from [ThreatTracer](https://github.com/anmolksachan/ThreatTracer/blob/main/threattracer.py) by [anmolksachan](https://github.com/anmolksachan).
# Contributing
Contributions are welcome! Please fork the repository and create a pull request with your changes.
# License
This project is licensed under the MIT License.

