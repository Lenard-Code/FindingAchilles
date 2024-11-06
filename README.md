# FindingAchilles
## Description
FindingAchilles is a Python-based tool designed to identify Common Vulnerabilities and Exposures (CVEs) for specified software and versions by querying various databases and sources.

## Requirements
Python 3.x
requests
beautifulsoup4
pyExploitDb
## Installation
Clone the repository:
sh
git clone https://github.com/Lenard-Code/FindingAchilles.git
cd FindingAchilles
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
# Contributing
Contributions are welcome! Please fork the repository and create a pull request with your changes.

# License
This project is licensed under the MIT License.

# Contact
For any questions or issues, please open an issue on GitHub.

