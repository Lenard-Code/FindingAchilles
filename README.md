<h1 align="center">
<b>FindingAchilles</b>
</h1>
<div align="center">
  <img src="/FindingAchilles.jpg" alt="FindingAchilles Logo" />
</div>

## Description
FindingAchilles is a Python-based Red/Blue Team tool designed to identify Common Vulnerabilities and Exposures (CVEs) for specified software and versions by querying various databases and sources. This was created based off the [ThreatTracer](https://github.com/anmolksachan/ThreatTracer/blob/main/threattracer.py) by [anmolksachan](https://github.com/anmolksachan) project but modified to handle a JSON input file. Further additions and modifications will continue to happen.

## Requirements
Python 3.x<br/>
NVD API Key<br/>
CVEDetails Bearer Token<br/>
requests<br/>
argparse<br/>
beautifulsoup4<br/>
pyExploitDb<br/>
nvdlib<br/>
## Installation
Clone the repository:<br/>
sh<br/>
git clone https://github.com/Lenard-Code/FindingAchilles.git<br/>
cd FindingAchilles<br/>
## Install the required dependencies:
pip install -r requirements.txt
## Usage
Prepare a JSON file containing software names and versions:
JSON<br/>
[<br/>
    {"name": "software1", "version": "1.0"},<br/>
    {"name": "software2", "version": "2.1"}<br/>
]<br/>
## Run the script:
python FindingAchilles.py path/to/your/json_file.json<br/>
<div align="center">
  <img src="/example.jpg" alt="example" />
</div>

## Acknowledgments</br>
This project makes use of code from [ThreatTracer](https://github.com/anmolksachan/ThreatTracer/blob/main/threattracer.py) by [anmolksachan](https://github.com/anmolksachan).<br/>
# Contributing
Contributions are welcome! Please fork the repository and create a pull request with your changes.<br/>
# License
This project is licensed under the MIT License.<br/>

