'''
 # @ Author: Newt Tan
 # @ Create Time: 2024-03-06 12:17:03
 # @ Modified by: Newt Tan
 # @ Modified time: 2024-03-07 13:57:39
 # @ Description: unit test for kvparser
 '''


import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

import unittest
from core.logparse.kvparser import KVParser

class TestLogparser(unittest.TestCase):
    ''' test the parsing performance for audit and process
    
    '''
    