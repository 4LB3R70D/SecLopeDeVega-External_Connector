"""
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega external connector
=================================================
Module: activity_register.py
Author: Alberto Dominguez 

This module contains code related to the register to get all activities 
of the external connections to be sent to the engine. This object is threat safe
"""
import base64
import logging
import threading
from datetime import datetime

from logic_modules.conversation_module import CAPTURES, RULE_ID
from utils.interoperability_py_go import (convert_py_bool_to_go_bool,
                                          interlanguage_bool_check)

# logger
logger = logging.getLogger(__name__)

# constants for preparing an activity object to be json-like element
ACTIVITY_ID = "ACTIVITY_ID"
TIME = "TIME"
CONNECTION_ID = "CONNECTION_ID"
NEW_CONN_FLAG = "NEW_CONN_FLAG"
ASYNC_ACTIVITY_FLAG = "ASYNC_ACTIVITY_FLAG"
TCP_CONN_READY_FLAG = "TCP_CONN_READY_FLAG"
IP = "IP"
PORT = "PORT"
EXT_INPUT = "EXT_INPUT"
GREETINGS_RULE = "GREETINGS_RULE"
DEFAULT_RULE = "DEFAULT_RULE"
EMPTY_RULE = "EMPTY_RULE"
EXECUTED_SYNC_RULES = "EXECUTED_SYNC_RULES"
EXECUTED_ASYNC_RULES = "EXECUTED_ASYNC_RULES"
CAPTURED_DATA = "CAPTURED_DATA"
DETECTED_ASYNC_RULES = "DETECTED_ASYNC_RULES"
END_CONNECTION = "END_CONNECTION"
LIST_CONNECTIONS_TIMED_OUT = "LIST_CONNECTIONS_TIMED_OUT"
CONN_BROKEN = "CONN_BROKEN"
PROTOCOL = "PROTOCOL"
ENCODING = "ENCODING"
MULTI_EXT_CONN_MEM = "MULTI_EXT_CONN_MEM"
GLOBAL_MEM = "GLOBAL_MEM"
CONN_MEM = "CONN_MEM"
HASH_CONV_RULES = "HASH_CONV_RULES"


class Activity:
    '''
    Object for each entry to add in the register
    '''

    def process_list_of_timed_out_connections(self, list_connections_timed_out):
        '''
        Method to prepare the list of timed out conenctions to save only the information needed to be sent
        '''
        list_of_timed_out_conn_ready_for_delivery = list()

        for conn in list_connections_timed_out:
            conn_ready_for_delivery = {
                "id": conn.id,
                "ip": conn.ip,
                "port": conn.port,
                "starting_time": conn.starting_time,
                "last_interaction": conn.last_interaction,
                "ending_time": conn.ending_time
            }
            list_of_timed_out_conn_ready_for_delivery.append(
                conn_ready_for_delivery)

        return list_of_timed_out_conn_ready_for_delivery

    def get_rules_id_list(self, list_conversation_rules):
        '''
        Method to get the conversation rules id of a set of rules
        '''
        rules_id_list = []
        for rule in list_conversation_rules:
            rules_id_list.append(rule.Id)

        return rules_id_list

    def get_json_ready_format(self):
        '''
        Method to seriealize an Activity object into a JSON-like element (dict)
        '''
        activity_json_ready = dict()
        activity_json_ready[ACTIVITY_ID] = self.id
        activity_json_ready[TIME] = self.date

        if hasattr(self, "connection_id"):
            activity_json_ready[CONNECTION_ID] = self.connection_id

        if hasattr(self, "new_conn_flag"):
            activity_json_ready[NEW_CONN_FLAG] = convert_py_bool_to_go_bool(
                self.new_conn_flag)

        if hasattr(self, "async_activity_flag"):
            activity_json_ready[ASYNC_ACTIVITY_FLAG] = convert_py_bool_to_go_bool(
                self.async_activity_flag)

        if hasattr(self, "tcp_conn_ready_flag"):
            activity_json_ready[TCP_CONN_READY_FLAG] = convert_py_bool_to_go_bool(
                self.tcp_conn_ready_flag)

        if hasattr(self, "ip"):
            activity_json_ready[IP] = self.ip

        if hasattr(self, "port"):
            activity_json_ready[PORT] = self.port

        if hasattr(self, "ext_input"):
            activity_json_ready[EXT_INPUT] = self.ext_input

        if hasattr(self, "greetings_rule"):
            activity_json_ready[GREETINGS_RULE] = convert_py_bool_to_go_bool(
                self.greetings_rule)

        if hasattr(self, "default_rule"):
            activity_json_ready[DEFAULT_RULE] = convert_py_bool_to_go_bool(
                self.default_rule)

        if hasattr(self, "empty_rule"):
            activity_json_ready[EMPTY_RULE] = convert_py_bool_to_go_bool(
                self.empty_rule)

        if hasattr(self, "executed_conv_rules"):
            activity_json_ready[EXECUTED_SYNC_RULES] = self.executed_conv_rules

        if hasattr(self, "executed_async_rules"):
            activity_json_ready[EXECUTED_ASYNC_RULES] = self.executed_async_rules

        if hasattr(self, "captured_data"):
            activity_json_ready[CAPTURED_DATA] = self.captured_data

        if hasattr(self, "detected_async_rules"):
            activity_json_ready[DETECTED_ASYNC_RULES] = self.detected_async_rules

        if hasattr(self, "end_connection"):
            activity_json_ready[END_CONNECTION] = convert_py_bool_to_go_bool(
                self.end_connection)

        if hasattr(self, "list_connections_timed_out"):
            # set() ==> list()
            activity_json_ready[LIST_CONNECTIONS_TIMED_OUT] = list(
                self.list_connections_timed_out)

        if hasattr(self, "conn_broken"):
            activity_json_ready[CONN_BROKEN] = convert_py_bool_to_go_bool(
                self.end_connection)

        if hasattr(self, "protocol"):
            activity_json_ready[PROTOCOL] = self.protocol

        if hasattr(self, "encoding"):
            activity_json_ready[ENCODING] = self.encoding

        if hasattr(self, "multi_ext_conn_mem"):
            activity_json_ready[MULTI_EXT_CONN_MEM] = self.multi_ext_conn_mem

        if hasattr(self, "global_mem"):
            activity_json_ready[GLOBAL_MEM] = self.global_mem

        if hasattr(self, "conn_mem"):
            activity_json_ready[CONN_MEM] = self.conn_mem

        # Only for the new connection activity
        if hasattr(self, "hash_conversation_rules_used") and self.new_conn_flag:
            activity_json_ready[HASH_CONV_RULES] = self.hash_conversation_rules_used

        return activity_json_ready

    def __init__(self, act_id, new_conn_flag, tcp_conn_ready_flag, ip, port, connection_id,
                 greetings_rule, executed_conv_rules, default_rule, empty_rule, ext_input,
                 detected_async_rules, captured_data, end_connection, async_activity_flag,
                 executed_async_rules, list_connections_timed_out, encoding, conn_broken,
                 multi_ext_conn_mem, global_mem, conn_mem, protocol, hash_conversation_rules_used,
                 encoded_b64_reported_memory):

        self.id = act_id
        self.date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.encoded_b64_reported_memory = encoded_b64_reported_memory

        # Information to report - general
        if connection_id is not None:
            self.connection_id = connection_id
        if new_conn_flag is not None:
            self.new_conn_flag = new_conn_flag
        if async_activity_flag is not None:
            self.async_activity_flag = async_activity_flag
        if tcp_conn_ready_flag is not None:
            self.tcp_conn_ready_flag = tcp_conn_ready_flag
        if ip is not None:
            self.ip = ip
        if port is not None:
            self.port = port
        if ext_input is not None:
            self.ext_input_b64 = base64.b64encode(
                ext_input.encode()).decode("utf-8")
        if encoding is not None:
            self.encoding = encoding
        if protocol is not None:
            self.protocol = protocol
        if hash_conversation_rules_used is not None:
            self.hash_conversation_rules_used = hash_conversation_rules_used

        # Information to report - conversation rules executed
        if greetings_rule is not None:
            self.greetings_rule = True
        if default_rule is not None:
            self.default_rule = True
        if empty_rule is not None:
            self.empty_rule = True
        if executed_conv_rules is not None:
            self.executed_conv_rules = self.get_rules_id_list(
                executed_conv_rules)
        if executed_async_rules is not None:
            self.executed_async_rules = self.get_rules_id_list(
                executed_async_rules)

        # Information to report - data captured for conversation rules
        if captured_data is not None and len(captured_data) > 0:
            self.captured_data = list()
            '''
            rule_data_captured = {
                    RULE_ID: rule.Id,
                    CAPTURES: dict() = {mod_mem_variable:raw_captured_value,...}
                }
            '''
            for rule_data_captured in captured_data:
                memory_mods = dict()
                for mod_mem_variable, raw_captured_value in rule_data_captured[CAPTURES].items():
                    memory_mods[mod_mem_variable] = base64.b64encode(
                        raw_captured_value.encode()).decode("utf-8")

                self.captured_data.append({
                    RULE_ID: rule_data_captured[RULE_ID],
                    CAPTURES: memory_mods
                })

        # Information to report - memory snapshot
        if multi_ext_conn_mem is not None:
            if encoded_b64_reported_memory:
                self.multi_ext_conn_mem = encode_b64_memory_elements(
                    multi_ext_conn_mem)
            else:
                self.multi_ext_conn_mem = multi_ext_conn_mem

        if global_mem is not None:
            if encoded_b64_reported_memory:
                self.global_mem = encode_b64_memory_elements(global_mem)
            else:
                self.global_mem = global_mem

        if conn_mem is not None:
            if encoded_b64_reported_memory:
                self.conn_mem = encode_b64_memory_elements(conn_mem)
            else:
                self.conn_mem = conn_mem

        # Information to report - conversation rules to be executed in a asyncrhonous way
        if detected_async_rules is not None:
            self.detected_async_rules = list(detected_async_rules.keys())

        # Information to report - ended connection/s
        if end_connection is not None:
            self.end_connection = end_connection
        if list_connections_timed_out is not None:
            self.list_connections_timed_out = self.process_list_of_timed_out_connections(
                list_connections_timed_out)
        if conn_broken is not None:
            self.conn_broken = conn_broken


def encode_b64_memory_elements(memory):
    '''
    Auxiliary function to encode the content of the memory variables using b64
    '''
    encoded_memory = dict()

    if memory is not None:
        for mem_var in memory:
            encoded_memory[mem_var] = base64.b64encode(
                str(memory[mem_var]).encode()).decode("utf-8")

    return encoded_memory


def sort_activities_to_be_sent(not_read_activities):
    '''
    Function to sort a list of activities in ascending order
    for being processed by the engine. The engine starts with the first one,
    so it is a kind of FIFO
    '''
    not_read_activities_sorted = list()
    first_time = True
    lowest_ID = 1
    greatest_ID = 1

    while (len(not_read_activities) > 0):
        lowest_ID_index = 0

        # find the lowest ID & greateast ID
        for index, activity in enumerate(not_read_activities):
            if activity[ACTIVITY_ID] <= lowest_ID:
                lowest_ID = activity[ACTIVITY_ID]
                lowest_ID_index = index

            # Only in the first time you check all activities, you find the
            # greateast activity
            if first_time and activity[ACTIVITY_ID] > greatest_ID:
                greatest_ID = activity[ACTIVITY_ID]

        # When the first time is over, change the flag
        if first_time:
            first_time = False

        if len(not_read_activities) > 0:
            not_read_activities_sorted.append(
                not_read_activities[lowest_ID_index])
            not_read_activities.remove(not_read_activities[lowest_ID_index])
            # Once the lowest value is found, we have to compare starting with the
            # largest ID value detected and going down from that point for the
            # next loop
            lowest_ID = greatest_ID
    return not_read_activities_sorted


class ActivityRegister:

    def __init__(self, encoded_b64_reported_memory):
        self.lock = threading.Lock()
        self.register = set()
        self.id_counter = 1
        self.encoded_b64_reported_memory = interlanguage_bool_check(
            encoded_b64_reported_memory)

    def get_new_id(self):
        '''
        Function to get a new connection ID & update the ID counter
        of the connection register
        '''
        with self.lock:
            id = self.id_counter
            self.id_counter += 1

        return id

    def add_activity(self, new_conn_flag=None, tcp_conn_ready_flag=None, ip=None, port=None,
                     connection_id=None, greetings_rule=None, executed_regex_conv_rules=None,
                     default_rule=None, empty_rule=None, detected_async_rules=None, captured_data=None,
                     end_connection=None, ext_input=None, async_activity_flag=None, executed_async_rules=None,
                     list_connections_timed_out=None, encoding=None, conn_broken=None, multi_ext_conn_mem=None,
                     global_mem=None, conn_mem=None, protocol=None, hash_conversation_rules_used=None):
        '''
        Method to add a new activity in the register
        '''
        new_act = Activity(self.get_new_id(), new_conn_flag, tcp_conn_ready_flag, ip, port, connection_id,
                           greetings_rule, executed_regex_conv_rules, default_rule, empty_rule, ext_input,
                           detected_async_rules, captured_data, end_connection, async_activity_flag,
                           executed_async_rules, list_connections_timed_out, encoding, conn_broken,
                           multi_ext_conn_mem, global_mem, conn_mem, protocol, hash_conversation_rules_used,
                           self.encoded_b64_reported_memory)

        with self.lock:
            self.register.add(new_act)

    def get_not_read_activities(self):
        '''
        Method to get a list of all new activities to be delivered to the engine
        '''
        not_read_activities = list()

        with self.lock:
            for activity in self.register.copy():
                # for each activity not already 'read'
                # https://stackoverflow.com/questions/10252010/serializing-class-instance-to-json
                not_read_activities.append(activity.get_json_ready_format())

                # Remove = read
                self.register.remove(activity)

                logger.info("New activity to send to the engine detected, " +
                            f"ID:{activity.id}")

        # sort the activities to be processed by the engine in the corresponding timely order
        not_read_activities_sorted = sort_activities_to_be_sent(
            not_read_activities)

        return not_read_activities_sorted
