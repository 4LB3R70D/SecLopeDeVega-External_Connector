"""
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega external connector
=================================================
Module: order_module.py
Author: Alberto Dominguez 

This is module contains the business logic about order management
"""

import logging
from enum import Enum

# logger
logger = logging.getLogger(__name__)


class OrderType(Enum):
    # 'Enum' of different order types
    NONE = "NONE"
    ACCEPT_CONN = "ACCEPT_CONN"
    NOT_ACCEPT_CONN = "NOT_ACCEPT_CONN"
    SHUTDOWN = "SHUTDOWN"
    REBOOT = "REBOOT"
    DISCONNECT = "DISCONNECT"


def accept_connections_order(context):
    '''
    Function to allow the external connector to accept new connections
    '''
    context.connection_register.modify_max_concurrent_connections(
        context.max_concurrent_connections)


def not_accept_connections_order(context):
    '''
    Function to enforce the external connector to not accepting new connections
    '''
    context.connection_register.modify_max_concurrent_connections(0)


def disconnect_all_connections_order(context):
    '''
    Function to end all current live connections by timing them out
    '''
    context.connection_register.timeout_all_connections()


def reboot_order(context):
    '''
    Function to reboot the external connector
    '''
    context.exec_dashboard.enable_restart_flag()
    shutdown_order(context)


def shutdown_order(context):
    '''
    Function to shutdown the external connector
    '''
    logger.warning("ENGINE HAS ORDERED TO SHUTDOWN THE EXTERNAL CONNECTOR!")
    not_accept_connections_order(context)
    disconnect_all_connections_order(context)
    context.exec_dashboard.end_execution()


def process_new_order(order_raw, context):
    '''
    Function to process a new order received from the engine
    '''
    if order_raw == OrderType.ACCEPT_CONN.value:
        accept_connections_order(context)

    elif order_raw == OrderType.NOT_ACCEPT_CONN.value:
        not_accept_connections_order(context)

    elif order_raw == OrderType.DISCONNECT.value:
        disconnect_all_connections_order(context)

    elif order_raw == OrderType.REBOOT.value:
        reboot_order(context)

    elif order_raw == OrderType.SHUTDOWN.value:
        shutdown_order(context)
