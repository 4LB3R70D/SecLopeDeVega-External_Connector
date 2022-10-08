"""
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega external connector
=================================================
Module: cleaening_register.py
Author: Alberto Dominguez 

This module contains a temporary register for saving the temp files locations 
to be cleaned before ending the execution of the external connector
"""

import threading
import os


class CleaningRegister:

    def __init__(self):
        self.lock = threading.Lock()
        self.list = set()

    def add_new_temp_file_location(self, path):
        '''
        Method to add a new temporary file
        '''
        with self.lock:
            self.list.add(path)

    def clean_all_temp_files(self):
        '''
        Method to clean all temproary files
        '''
        with self.lock:
            for path_temp_file in self.list:
                if path_temp_file is not None and os.path.exists(path_temp_file):
                    os.remove(path_temp_file)
