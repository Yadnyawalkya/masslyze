# masslyze

Small tool to analyse the XML output of [sslyze](https://github.com/nabla-c0d3/sslyze) in order to provide an overview on mass SSL scans of IP ranges.

### Version
0.2

### Installation & Usage
##### Requirements:
Masslyze is designed for Windows use. Tested against Python >= 3.3 No dependencies beside a compiled copy of [sslyze](https://github.com/nabla-c0d3/sslyze) in the same folder (needed for scans, not for analyse only).

##### Directory structure:
```
+--masslyze.py
+--functions/
|     +--helper_functions.py
|     +--output_generation.py
|     +--vulnerability_checks.py
+-- sslyze/
      +--sslyze.exe
      + ...
```

##### Analyse only:
- Download files
- run:
```sh
$ python masslyze.py -a path_to_sslyze_XML_output.xml
```
- Output in: output.txt and output_sorted_by_hosts.txt

##### Scan & analyse:
- Download files
- add [compiled version of sslyze](https://github.com/nabla-c0d3/sslyze/releases) to same directory
- create text file with targethost:port each in a new line
- run:
```sh
$ python masslyze.py -sa path_to_txt_file_with_targethosts.txt
```
- wait until scan and analyse is finished
- Output in: output.txt and output_sorted_by_hosts.txt


### Version history

##### 0.2
- bugfixes
- added functionallity: generate output sorted by hosts

##### 0.1
- init. Version
- analyse XML output of sslyze
- generate output sorted by vulnerability class