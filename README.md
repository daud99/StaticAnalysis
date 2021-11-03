## Malware Static Analysis

### Initial Setup
1. Install Virtualenv
```shell
pip install virtualenv
```
2. Create Virtualenv
```shell
virtualenv venv
```
3. Activate Virtualenv
```shell
source venv/bin/activate
```
4. Install Dependencies
```shell
pip install -r requirements.txt
```
4. Making script executable
```shell
chmod +x analysis.py
```

### Usage

```shell
Usage: analysis.py [option(s)] [path]
Calculate hashes, find strings, file types and extract useful different PE file formatsThe options are:
The options are:
        --file                                  Specify that given path is the path of single file
        --folder                                Specify that given path is the path of folder containing files
        --csv[default=False]                    Exporting csv file
        --display[default=True]                 Display the findings
        --csv-name                              Specify the name of exporting csv file
        --csv-path[default=pwd]                 Specify the path where to store the resultant csv file
        --string-file-path[default=pwd]         Specify the path where to store the resultant string files
        --discover-file-path[default=pwd]       Specify the path where to store the resultant discover_pe files
Either --file or --folder can be use one at a time. Both can't be used at the same time.
Report bugs to: daudahmed@zoho.com
```

#### For instance

>```(venv)(daud㉿kali)-[~/MA/code]└─$ ./analysis.py --file "/home/daud/MA/malware-analysis-samples/samples/stub.bin" --csv-path "/home/daud/MA/code/csv/" --discover-file-path "/home/daud/MA/code/discover" --string-file-path "/home/daud/MA/code/string" --display true --csv false```
