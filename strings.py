#!/usr/bin/env python
import os
import subprocess

def findStrings(file, directory=''):
    file_name = f'strings-{file.name}.txt'
    if directory: file_name = os.path.join(directory, file_name)
    with open(file_name, 'w') as f:
        subprocess.run(["strings", "-a", file.path], stdout=f, text=True)
