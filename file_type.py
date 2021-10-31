#!/usr/bin/env python
import os
import csv
import magic
import hash_malware
def performFileAnalysis(file=None, display=False, csv_file=None):
    '''
    performFileAnalysis given the file path
    :param file: The path of the file
    :type file: string
    :param display: To enable or disable printing the file type on terminal/shell
    :type display: boolean
    :param csv: To enable or disable exporting file types in CSV format in case you want to export csv just pass in the name of the file
    :type csv: string
    '''
    hashes = True
    header = ["File Name", "File Type using from_file", "File Type using from_buffer", "File Type using from_file with MIME"]

    if hashes: header.extend(["md5", "sha1", "sha256"])
    hashes_list = []
    if file == None:
        return
    try:
        file_type_1 = magic.from_file(file.path)
        file_type_2 = magic.from_buffer(open(file.path, 'rb').read(2048))
        file_type_3 = magic.from_buffer(open(file.path, 'rb').read(2048), mime=True)
        if display: printFileTypeInfo(file, file_type_1, file_type_2, file_type_3)
        append_header = True
        if hashes: hashes_list = hash_malware.computeHashes(file.path)
        if(csv_file and os.path.exists(csv_file)): append_header = False
        if csv_file:
            with open(csv_file,  'a', newline='') as f:
                writer = csv.writer(f)
                if append_header: writer.writerow(header)
                writer.writerow([file.name, file_type_1, file_type_2, file_type_3, *hashes_list])

    except Exception as e:
        print("Error detemining file type")
        print(e)


def printFileTypeInfo(file, file_type_1, file_type_2, file_type_3):
    '''
    Simply display the FileType in the Terminal
    :param file: The file object
    :type file: DirEntry
    :param file_type_1: The file type determine using from_file method
    :type file_type_1: str
    :param file_type_2: The file type determine using from_buffer method
    :type file_type_2: str
    :param file_type_3: The file type determine using from_buffer method with MIME
    :type file_type_3: str
    '''

    print(''.join(['-' for x in range(1, 150)]))
    print(f'File name: {file.name}\n')
    print(f'File type with method from_file: {file_type_1}\n')
    print(f'File type with method from_buffer: {file_type_2}\n')
    print(f'File type with method from_buffer with MIME: {file_type_3}\n')
    print(''.join(['-' for x in range(1, 150)]))

