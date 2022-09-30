"""
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega external connector
=================================================
Module: exec_dashboard.py
Author: Alberto Dominguez 

This module contains code to manage the overall execution of the external connection 
by providing an object to store some information and providing thread safe capabilties 
(using locks)
"""
import logging
import threading
import time

from logic_modules import order_module as ord_mod

# logger
logger = logging.getLogger(__name__)


class ExecDashboard:

    def __init__(self, ext_connector_starting_time, timeout_ext_conn):

        self.lock = threading.Lock()
        self.order_register = set()
        self.execution_enable = True
        self.id_order_counter = 1
        self.execution_restart = False
        self.interaction_started = False

        #  Ext connector timeout (when the execution is going to end)
        if timeout_ext_conn:
            self.execution_ending_time = ext_connector_starting_time + timeout_ext_conn
            logger.info("The external connector is configured to be running until: " +
                        f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.execution_ending_time))}")
        else:
            self.execution_ending_time = None
            logger.warn(
                "The external connector is configured to run 'FOREVER'")

    def get_new_id(self):
        '''
        Function to get a new connection ID & update the ID counter
        of the connection register
        '''
        with self.lock:
            id = self.id_order_counter
            self.id_counter += 1

        return id

    def add_new_order(self, order):
        '''
        Method to add a new order in the execution dashboard
        TODO
        '''
        order_id = self.get_new_id()
        order = ord_mod.Order(order_id)

        with self.lock:
            self.order_register.add(order)

    def reached_execution_timeout(self):
        '''
        Method to control if the execution should be ended
        '''
        now = time.time()
        # Variable to return
        result = False

        with self.lock:
            # if Not null/None and larger than the 'execution ending time'
            if (self.execution_ending_time is not None) and (now >= self.execution_ending_time):
                result = True

        return result

    def check_execution_flag(self):
        '''
        Method to check the execution flag
        '''
        with self.lock:
            result = self.execution_enable

        return result

    def end_execution(self):
        '''
        Method to signal that the execution should be ended
        '''
        logger.warn(
            "External connector execution flag disable ==> ENDING EXECUTION!")
        with self.lock:
            self.execution_enable = False

    def check_restart_flag(self):
        '''
        Method to check if the execution should be restarted. If so,
        the value is set to false
        '''
        result = False
        with self.lock:
            if self.execution_restart:
                result = True
                self.execution_restart = False
        return result
    
    def enable_restart_flag(self):
        '''
        Method to enable the external connector restart flag
        '''
        with self.lock:
            self.execution_restart = True
            
    def mark_interaction_as_started(self):
        '''
        Method to mark that interaction with external elemens has started
        '''
        with self.lock:
            self.interaction_started = True
            
    def is_interaction_started(self):
        '''
        Method to return if the interaction with external elemens has started
        '''
        with self.lock:
            result = self.interaction_started
            
        return result

