#!/usr/bin/env python
from datetime import datetime
import sys
import os

from file_type import performFileAnalysis
import strings
import discover_pe

class dotdict(dict):
    """dot.notation access to dictionary attributes"""
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

class FileExtractor():
    '''
    FileExtractor object extract the files present in the given Folder
    :param path: The path of the folder
    :type path: str
    '''

    def __init__(self, path):
        self.__path = path

    def getFiles(self):
        '''
        getFiles return the generator object for all the files in the directory

        :returns: file object generator
        '''

        for each in os.scandir(self.__path):
            if each.is_file():
                yield each

def showHelp():
    print("Usage: mains [option(s)] [path]\n"
          "Calculate hashes, find strings, file types and extract useful different PE file formatsThe options are:\n"
          "The options are:\n"
          "\t--file\t\t\t\t\tSpecify that given path is the path of single file\n"
          "\t--folder\t\t\t\tSpecify that given path is the path of folder containing files\n"
          "\t--csv[default=False]\t\t\t\tExporting csv file\n"
          "\t--display[default=True]\t\t\t\tDisplay the findings\n"
          "\t--csv-name\t\t\t\tSpecify the name of exporting csv file\n"
          "\t--csv-path[default=pwd]\t\t\tSpecify the path where to store the resultant csv file\n"
          "\t--string-file-path[default=pwd]\t\tSpecify the path where to store the resultant string files\n"
          "\t--discover-file-path[default=pwd]\tSpecify the path where to store the resultant discover_pe files\n"
          "Either --file or --folder can be use both can't be used at the same time.\n"
          "Report bugs to: daudahmed@zoho.com")

if "__main__" == __name__:
    '''
    '''
    if ("--help" in sys.argv) or ("--folder" in sys.argv and "--file" in sys.argv):
        showHelp()
    else:
        # folder_path = "/home/daud/MA/malware-analysis-samples/samples/"
        folder_path = None
        file_path = None
        csv_path = ''
        string_file_path = ''
        discover_file_path = ''
        csv = False
        display = True
        csv_file = f'filetype-{str(datetime.now())}.csv'
        if("--folder" in sys.argv):
            i = sys.argv.index("--folder")
            folder_path = sys.argv[i+1]
        if "--file" in sys.argv:
            i = sys.argv.index("--file")
            file_path = sys.argv[i+1]
        if "--csv" in sys.argv:
            i = sys.argv.index("--csv")
            if sys.argv[i+1].lower() == "true": csv = True

        if "--display" in sys.argv:
            i = sys.argv.index("--display")
            if sys.argv[i+1].lower() == "false": display = False
        if "--csv-name" in sys.argv:
            i = sys.argv.index("--csv-name")
            csv_file = sys.argv[i+1]
        if "--csv-path" in sys.argv:
            i = sys.argv.index("--csv-path")
            csv_path = os.path.join(sys.argv[i+1], csv_file)
        if "--string-file-path" in sys.argv:
            i = sys.argv.index("--string-file-path")
            string_file_path = sys.argv[i+1]
        if "--discover-file-path" in sys.argv:
            i = sys.argv.index("--discover-file-path")
            discover_file_path = sys.argv[i+1]
        if csv_path: csv_file = csv_path
        if not csv: csv_file = None
        if folder_path:
            file_extractor = FileExtractor(folder_path)
            files = file_extractor.getFiles()
            for each in files:
                performFileAnalysis(each, display, csv_file)
                strings.findStrings(each, string_file_path)
                discover_pe.discoverPE(each, discover_file_path)
        elif file_path:
            f = {"name": os.path.basename(file_path), "path": file_path}
            f = dotdict(f)
            performFileAnalysis(f, display, csv_file)
            strings.findStrings(f, string_file_path)
            discover_pe.discoverPE(f, discover_file_path)



