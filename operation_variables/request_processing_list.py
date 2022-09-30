"""
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega external connector
=================================================
Module: request_processing_list.py
Author: Alberto Dominguez 

This module contains code related to manage when a request from a connection (mainly a tcp one)
is being processed. If so, not new connections from one IP and PORT should be accepted until the 
exiting request is answered. It manages two list, one for the new connections and other for the 
existing ones. The lifecycle should be as follows: 
ADD => new conn list => existing conn list => REMOVE (request complete)
"""
import logging
import threading

# logger
logger = logging.getLogger(__name__)

# locks for ensuring thread safe
request_processing_lock = threading.Lock()

# request processing lists for managing connections
list_for_new_tcp_conn = set()
list_for_existing_tcp_conn = set()
# Only in use when the option close after
list_for_managing_conn_closing_after_answering = set()

# ==========================================================================================
# ADDING FUNCTIONS
# ==========================================================================================


def add_request_in_processing_list_for_new_conn(addr):
    '''
    Function to add a new request in the processing list for new connections
    '''
    with request_processing_lock:
        list_for_new_tcp_conn.add(addr)


def add_request_in_processing_list_for_existing_conn(addr):
    '''
    Function to add a new request in the processing list for existing connections
    '''
    with request_processing_lock:
        list_for_existing_tcp_conn.add(addr)


def add_request_in_processing_list_for_managing_conn_closing_after_answering(addr):
    '''
    Function to add a new request in the processing list for the connections that should be 
    closed once all the answers are delivered
    '''
    with request_processing_lock:
        list_for_managing_conn_closing_after_answering.add(addr)


# ==========================================================================================
# REMOVING FUNCTIONS
# ==========================================================================================


def remove_request_from_processing_list_for_new_conn(addr):
    '''
    Function to add a new request in the processing list of existing connections requests
    '''
    success = False
    with request_processing_lock:
        if addr in list_for_new_tcp_conn:
            list_for_new_tcp_conn.remove(addr)
            success = True
    if not success:
        logger.debug(f"Request from: {addr}, not found in the request processing list of "
                       + "existing connection requests")


def remove_request_from_processing_list_for_existing_conn(addr):
    '''
    Function to add a new request in the processing list of existing connections requests
    '''
    success = False
    with request_processing_lock:
        if addr in list_for_existing_tcp_conn:
            list_for_existing_tcp_conn.remove(addr)
            success = True
    if not success:
        logger.debug(f"Request from: {addr}, not found in the request processing list of "
                       + "existing connection requests")


def remove_request_from_processing_list_for_managing_conn_closing_after_answering(addr):
    '''
    Function to add a new request in the processing list for the connections that should be 
    closed once all the answers are delivered
    '''
    success = False
    with request_processing_lock:
        if addr in list_for_managing_conn_closing_after_answering:
            list_for_managing_conn_closing_after_answering.remove(addr)
            success = True
    if not success:
        logger.debug(f"Request from: {addr}, not found in the request processing list for "
                       + "managing closing of connections")

# ==========================================================================================
# CHECKING FUNCTIONS
# ==========================================================================================


def check_request_in_processing_list_for_new_conn(addr):
    '''
    Function to check if a request is in the processing list for new connections
    '''
    with request_processing_lock:
        result = addr in list_for_new_tcp_conn
    return result


def check_request_in_processing_list_for_exiting_conn(addr):
    '''
    Function to check if a request is in the processing list for existing connections
    '''
    with request_processing_lock:
        result = addr in list_for_existing_tcp_conn
    return result


def check_request_in_processing_list_for_new_or_exiting_conn(addr):
    '''
    Method to check if a request is either in the new connection list or in the existing connection list
    '''
    with request_processing_lock:
        result = addr in list_for_new_tcp_conn or addr in list_for_existing_tcp_conn
    return result


def check_request_in_processing_list_for_managing_conn_closing_after_answering(addr):
    '''
    Function to check if a request is in the processing list for the connections that should be 
    closed once all the answers are delivered
    '''
    with request_processing_lock:
        result = addr in list_for_managing_conn_closing_after_answering
    return result
