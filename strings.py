#!/usr/bin/env python

import subprocess

def findStrings(file):
    file_name = f'strings-{file.name}.txt'
    with open(file_name, 'w') as f:
        subprocess.run(["strings", "-a", file.path], stdout=f, text=True)
