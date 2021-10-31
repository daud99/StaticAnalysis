#!/usr/bin/env python
from datetime import datetime
import os

from file_type import performFileAnalysis

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


if "__main__" == __name__:
    folder_path = "/home/daud/MA/malware-analysis-samples/samples/"
    csv_file = f'filetype-{str(datetime.now())}'
    file_extractor = FileExtractor(folder_path)
    files = file_extractor.getFiles()
    for each in files:
        performFileAnalysis(each, True, csv_file, True)

