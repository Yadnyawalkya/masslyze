# masslyze

Small tool to analyse the XML output of sslyze in order to provide a n overview on mass SSL scans of IP ranges.

### Version
0.1

### Installation & Usage
##### Requirements:
Masslyze is designed for Windows use. Tested against Python >= 3.3 No dependencies beside a compiled copy of [sslyze](https://github.com/nabla-c0d3/sslyze) in the same folder.

##### Analyse only:
- Download files
- run:
```sh
$ python masslyze.py -a path_to_sslyze_XML_output.xml
```
- Output in output.txt
##### Scan & analyse:
- Download files
- add [compiled version of sslyze](https://github.com/nabla-c0d3/sslyze/releases) to same directory
- create text file with targethost:port each in a new line
- run:
```sh
$ python masslyze.py -sa path_to_txt_file_with_targethosts.txt
```
- wait until scan and analyse is finished
- Output in output.txt

