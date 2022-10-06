"""
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega external connector
=================================================
Module: operation_worker.py
Author: Alberto Dominguez

This module contains the business logic of operation worker, which is in charge of
executing the conversation rules and update the connection status according to the operation loop
"""
import base64
import logging
import re
import subprocess
import time

import logic_modules.conversation_module as conv_mod
from operation_variables import connection
from operation_variables.connection_register import (CONN_MEMORY,
                                                     GLOBAL_MEMORY,
                                                     MULTI_EXT_CONNECTORS)
from operation_variables.request_processing_list import (
    add_request_in_processing_list_for_managing_conn_closing_after_answering,
    check_request_in_processing_list_for_managing_conn_closing_after_answering)
from utils import connection_utils
from utils.interoperability_py_go import interlanguage_bool_check

# logger
logger = logging.getLogger(__name__)

# constants
NUMBER_CHAR_THREAD_NAME_TOKEN = 5
OP_WORKER_PREFIX_NAME = "OpWrkr-"
BANNER_COMMAND_LINE_ARGS_KEY_SHORT = "-NB"
CONFIG_COMMAND_LINE_ARGS_KEY_SHORT = "-CFG"
ID_COMMAND_LINE_ARGS_KEY_SHORT = "-ID"
PASS_COMMAND_LINE_ARGS_KEY_SHORT = "-PWD"


def get_thread_name():
    '''
    Method to create a random threat name
    '''
    name = OP_WORKER_PREFIX_NAME + \
        connection_utils.select_characters_from_dict(
            connection_utils.ALPHANUMERIC_DICT, NUMBER_CHAR_THREAD_NAME_TOKEN)
    return name


class OperationWorker:
    '''
    Object to provide the tools that operation workers need to manage the operation tool
    from the external thrid party
    '''

    def __init__(self, conversation_rules, connection_register, activity_register, todo_list,
                 exec_dashboard, ext_conn_controller, hash_conversation_rules_used, 
                 cleaning_register, custom_functions_name, number_rule_checker_subworkers):

        self.cnv_rules = conversation_rules
        self.connection_register = connection_register
        self.activity_register = activity_register
        self.todo_list = todo_list
        self.exec_dashboard = exec_dashboard
        self.thread_name = get_thread_name()
        self.ext_conn_controller = ext_conn_controller
        self.hash_conversation_rules_used = hash_conversation_rules_used
        self.cleaning_register = cleaning_register
        self.custom_functions_name = custom_functions_name
        self.number_rule_checker_subworkers = number_rule_checker_subworkers

    # =========================================================================================
    # Identifying conection methods
    # =========================================================================================
    def identify_connection(self, ip, port, conn_socket=None, recv_data=None, client_socket_id=None):
        '''
        Method to identify a connection, or create a new one if not found
        '''
        connection_copy = None
        enable_rule_triggered_close_socket = self.connection_register.enable_rule_triggered_close_socket
        tcp_or_dtls_socket_close_after_answering_mode = (
            (self.ext_conn_controller.udp_protocol and self.ext_conn_controller.encrypted) or
            not self.ext_conn_controller.udp_protocol) and self.connection_register.close_tcp

        if ip is not None and len(ip) > 0:
            found, connection_copy, session_id = self.connection_register.find_active_connection_using_ip(
                source_ip=ip,
                source_port=port,
                recv_data=recv_data,
                connection_socket=conn_socket)

            # not found and client mode and close tcp/dtls socket after answer (global or rule triggered)
            if not found and self.connection_register.client_mode and (
                    tcp_or_dtls_socket_close_after_answering_mode or enable_rule_triggered_close_socket):
                addr = (ip, port, client_socket_id)
                if not check_request_in_processing_list_for_managing_conn_closing_after_answering(addr):
                    connection_copy = self.connection_register.add_new_connection(
                        source_ip=ip,
                        source_port=port,
                        connection_socket=conn_socket,
                        session_value=session_id,
                        client_socket_id=client_socket_id)

                    add_request_in_processing_list_for_managing_conn_closing_after_answering(
                        addr)
                    if connection_copy is not None:
                        self.connection_register.reset_sync_done_async_in_progress_flag_of_a_connection(
                            connection_copy.id)

            # not found and server mode and close tcp/dtls socket after answer (global or rule triggered)
            elif not found and not self.connection_register.client_mode and (
                    tcp_or_dtls_socket_close_after_answering_mode or
                    enable_rule_triggered_close_socket):
                addr = (ip, port)
                if not check_request_in_processing_list_for_managing_conn_closing_after_answering(addr):
                    connection_copy = self.connection_register.add_new_connection(
                        source_ip=ip,
                        source_port=port,
                        connection_socket=conn_socket)
                    add_request_in_processing_list_for_managing_conn_closing_after_answering(
                        addr)
                    if connection_copy is not None:
                        self.connection_register.reset_sync_done_async_in_progress_flag_of_a_connection(
                            connection_copy.id)

            # not found and server mode and not close tcp/dtls socket after answer (global or rule triggered)
            elif not found and not self.connection_register.client_mode and \
                    not (tcp_or_dtls_socket_close_after_answering_mode or enable_rule_triggered_close_socket):
                connection_copy = self.connection_register.add_new_connection(
                    source_ip=ip,
                    source_port=port,
                    connection_socket=conn_socket)

            # not found and client mode and not close tcp/dtls socket after answer (global or rule triggered)
            elif not found and self.connection_register.client_mode and \
                    not (tcp_or_dtls_socket_close_after_answering_mode or enable_rule_triggered_close_socket):
                connection_copy = self.connection_register.add_new_connection(
                    source_ip=ip,
                    source_port=port,
                    connection_socket=conn_socket,
                    session_value=session_id,
                    client_socket_id=client_socket_id)

            # found and client mode and close tcp/dtls socket after answer (global or rule triggered)
            elif found and self.connection_register.client_mode and (
                    tcp_or_dtls_socket_close_after_answering_mode or
                    enable_rule_triggered_close_socket):
                addr = (ip, port, client_socket_id)
                if not check_request_in_processing_list_for_managing_conn_closing_after_answering(addr):
                    add_request_in_processing_list_for_managing_conn_closing_after_answering(
                        addr)
                    if connection_copy is not None:
                        self.connection_register.reset_sync_done_async_in_progress_flag_of_a_connection(
                            connection_copy.id)

            # found and server mode and close tcp/dtls socket after answer (global or rule triggered)
            elif found and not self.connection_register.client_mode and (
                    tcp_or_dtls_socket_close_after_answering_mode or
                    enable_rule_triggered_close_socket):
                addr = (ip, port)
                if not check_request_in_processing_list_for_managing_conn_closing_after_answering(addr):
                    add_request_in_processing_list_for_managing_conn_closing_after_answering(
                        addr)
                    if connection_copy is not None:
                        self.connection_register.reset_sync_done_async_in_progress_flag_of_a_connection(
                            connection_copy.id)

            if not found and connection_copy is not None:
                self.update_act_register(
                    new_conn_flag=True,
                    ip=ip,
                    port=port,
                    connection_id=connection_copy.id)
        else:
            logger.warning(
                "IP is None or an empty string at the time to identify a connection!")

        return connection_copy

    # =========================================================================================
    # Memory/Session related methods
    # =========================================================================================
    def do_memory_updates(self, list_of_memory_var_to_updates, memory_type, connection_id=None):
        '''
        Method to do the corresponding memory updates using a list (dict), where the key is the variable name
        and the value is the new value of the memory variable
        '''
        if len(list_of_memory_var_to_updates) > 0:
            for mem_var_name, mem_var_new_value in list_of_memory_var_to_updates.items():
                success = self.connection_register.modify_memory_variable(
                    mem_var_name, mem_var_new_value, memory_type, connection_id)
                logger.info(
                    f"Was the process of updating of the memory variable:{mem_var_name} successful?: {success}")
        else:
            logger.info(
                f"No memory variables to update for the memory:{memory_type} and the connection:{connection_id}")

    def get_memories_copy(self, connection_id):
        '''
        Method to get a copy of the current memories (global and a connection one)
        '''
        # get a copy of the multi external cloud memory, global memory and the connection memory
        multi_ext_conn_mem = self.connection_register.get_copy_multi_ext_connectors_memory()
        global_mem = self.connection_register.get_copy_global_memory()
        conn_mem = self.connection_register.get_copy_conn_memory(connection_id)
        return multi_ext_conn_mem, global_mem, conn_mem

    def update_memories(self, connection_copy, conv_rules, captured_data):
        '''
        Method to update the simulation memories, according to the rules and/or the captured data.

        First captured data is the one used to modify the memory, later on, the rules. If a memory value is
        in both list, the one that is related to a rule will remain.
        '''
        # get a copy of the multi external cloud memory, global memory and the connection memory
        multi_ext_conn_mem, global_mem, conn_mem = self.get_memories_copy(
            connection_copy.id)

        memory_mod_for_capturing_multi_ext_conn_mem, memory_mod_for_capturing_global, \
            memory_mod_for_capturing_conn = conv_mod.get_potential_memory_mods_using_captured_data(
                captured_data,
                multi_ext_conn_mem,
                global_mem,
                conn_mem)

        memory_mod_for_rules_multi_ext_conn_mem, memory_mod_for_rules_global, memory_mod_for_rules_conn =\
            conv_mod.get_potential_memory_mods_using_rules(
                conv_rules,
                multi_ext_conn_mem,
                global_mem,
                conn_mem)

        logger.info(
            f"Updating memory values according to the events in the connection:{connection_copy.id}...")

        # https://thispointer.com/how-to-merge-two-or-more-dictionaries-in-python/
        final_memory_mod_multi = {
            **memory_mod_for_capturing_multi_ext_conn_mem,
            **memory_mod_for_rules_multi_ext_conn_mem}
        final_memory_mod_global = {
            **memory_mod_for_capturing_global, **memory_mod_for_rules_global}
        final_memory_mod_conn = {
            **memory_mod_for_capturing_conn, **memory_mod_for_rules_conn}

        self.do_memory_updates(final_memory_mod_multi, MULTI_EXT_CONNECTORS)
        self.do_memory_updates(final_memory_mod_global, GLOBAL_MEMORY)
        self.do_memory_updates(final_memory_mod_conn,
                               CONN_MEMORY, connection_copy.id)

    def execute_memory_operations(self, connection_copy, external_input,
                                  rules_list, custom_functions_flag):
        '''
        Method to execute builtin memory operations or custom functions
        (if any) registered in the corresponding list of
        conversation rules (executed or detected ones).
        '''
        # get a copy of the multi external cloud memory, global memory and the connection memory
        multi_ext_conn_mem, global_mem, conn_mem = self.get_memories_copy(
            connection_copy.id)

        # Custom memory operations
        if custom_functions_flag:
            memory_mod_multi, memory_mod_global, memory_mod_conn =\
                conv_mod.get_potential_memory_mods_using_custom_functions(
                    rules_list,
                    external_input,
                    multi_ext_conn_mem,
                    global_mem,
                    conn_mem,
                    connection_copy.ip,
                    connection_copy.port,
                    connection_copy.session_key,
                    connection_copy.session_value,
                    self.custom_functions_name)

        # Builtin memory operations
        else:
            memory_mod_multi, memory_mod_global, memory_mod_conn =\
                conv_mod.get_potential_memory_mods_using_bultin_mem_ops(
                    rules_list,
                    external_input,
                    multi_ext_conn_mem,
                    global_mem,
                    conn_mem,
                    connection_copy.ip,
                    connection_copy.port,
                    connection_copy.session_key,
                    connection_copy.session_value)

        self.do_memory_updates(memory_mod_multi, MULTI_EXT_CONNECTORS)
        self.do_memory_updates(memory_mod_global, GLOBAL_MEMORY)
        self.do_memory_updates(memory_mod_conn,
                               CONN_MEMORY, connection_copy.id)

    def evaluate_rule_for_session_id_change(self, rule, connection_copy):
        '''
        Method to check if a given specific rule triggers a session ID change, and execute it
        '''
        if interlanguage_bool_check(rule.SessionUpdate.Enable):
            multi_ext_conn_mem, memory_global, memory_conn = self.get_memories_copy(
                connection_copy.id)
            update_flag = False
            logger.info(
                f"Detected conversation rule applicable for " +
                f"session ID change, rule id:{rule.Id}")

            # Session ID modification using memory variables
            if len(rule.SessionUpdate.MemoryVariable) > 0:
                update_flag = True
                if rule.SessionUpdate.MemoryVariable in multi_ext_conn_mem:
                    session_value = multi_ext_conn_mem[rule.SessionUpdate.MemoryVariable]
                elif rule.SessionUpdate.MemoryVariable in memory_global:
                    session_value = memory_global[rule.SessionUpdate.MemoryVariable]
                elif rule.SessionUpdate.MemoryVariable in memory_conn:
                    session_value = memory_conn[rule.SessionUpdate.MemoryVariable]
                else:
                    update_flag = False
                    logger.warn(f"Memory variable '{rule.SessionUpdate.MemoryVariable}' not found" +
                                f" for modifying the session ID of the connection:{connection_copy.id}")

            # Sessiond ID modification using autogenerated session ID
            elif interlanguage_bool_check(rule.SessionUpdate.AutogeneratedValue):
                update_flag = True
                session_value = connection_utils.get_autogenerated_token(
                    connection_copy.session_value_type_chars,
                    connection_copy.session_value_numb_chars)

            # Sessiond ID modification using a fised session ID value
            elif len(rule.SessionUpdate.FixedValue) > 0:
                update_flag = True
                session_value = rule.SessionUpdate.FixedValue

            if update_flag:
                connection_copy =\
                    self.connection_register.update_session_id_of_a_connection(
                        connection_copy.id,
                        session_value)
                logger.info(
                    f"Session ID changed in the connection:{connection_copy.id}, new value:{session_value}")
        return connection_copy

    def transform_async_rules_in_original_format_rules(self, async_conv_rules):
        '''
        Auxiliary function to transform the list of async rules in a list of rules with the
        original format
        '''
        rule_list = list()
        for _, _, rule in async_conv_rules.values():
            rule_list.append(rule)
        return rule_list

    def check_and_do_memory_updates(self, connection_copy, detection_time,
                                    conv_rules_original_format=None,
                                    async_conv_rules=None, captured_data=None):
        '''
        Method to check if the time to update the memories is the correct one, and then, do it
        '''
        if self.connection_register.memory_update_when_detected == detection_time:  # expected time to do it?
            logger.info(
                "Memory update functionality enable, " +
                f"checking rules for the connection:{connection_copy.id}")
            if conv_rules_original_format is not None:
                self.update_memories(
                    connection_copy, conv_rules_original_format, captured_data)
            elif async_conv_rules is not None:
                rules_list = self.transform_async_rules_in_original_format_rules(
                    async_conv_rules)
                self.update_memories(
                    connection_copy, rules_list, captured_data)

    def check_and_execute_mem_operations(
            self, connection_copy,
            detection_time, conv_rules_original_format,
            custom_functions_flag, external_input=None, async_conv_rules=None):
        '''
        Method to check and execute custom functions (functions defined by the operator)
        '''
        if self.connection_register.custom_function_when_detected == detection_time:  # expected time to do it?
            logger.info(
                f"Custom Function execution enable, executing them for the connection:{connection_copy.id}")
            if conv_rules_original_format is not None:
                self.execute_memory_operations(
                    connection_copy, external_input,
                    conv_rules_original_format, custom_functions_flag)
            elif async_conv_rules is not None:
                rules_list = self.transform_async_rules_in_original_format_rules(
                    async_conv_rules)
                self.execute_memory_operations(
                    connection_copy, external_input, rules_list, custom_functions_flag)

    def check_and_execute_custom_function_pre_post_processor(self, raw_input_output,
                                                             connection_copy, preprocessor_flag):
        """
        Method to check and execute the custom function preprocessor
        for any input received from outside before starting
        the normal processing flow; or post processor
        for the output to return after the execution of a rule
        """
        if preprocessor_flag:
            custom_function = self.connection_register.custom_function_preprocessor
        else:
            custom_function = self.connection_register.custom_function_postprocessor

        if custom_function is not None and interlanguage_bool_check(custom_function.Enable):

            # get a copy of the multi external cloud memory, global memory and the connection memory
            multi_ext_conn_mem, global_mem, conn_mem = self.get_memories_copy(
                connection_copy.id)

            if preprocessor_flag:
                logger.debug("Executing the custom function preprocessor...")
            else:
                logger.debug("Executing the custom function postprocessor...")

            memory_mod_multi, memory_mod_global, memory_mod_conn, processed_input_output =\
                conv_mod.execute_custom_function_pre_post_processor(
                    raw_input_output, custom_function, multi_ext_conn_mem,
                    global_mem, conn_mem, connection_copy.ip, connection_copy.port,
                    connection_copy.session_key, connection_copy.session_value, 
                    self.custom_functions_name)

            self.do_memory_updates(memory_mod_multi, MULTI_EXT_CONNECTORS)
            self.do_memory_updates(memory_mod_global, GLOBAL_MEMORY)
            self.do_memory_updates(memory_mod_conn,
                                   CONN_MEMORY, connection_copy.id)
        else:
            processed_input_output = raw_input_output
            logger.debug(
                "Custom function preprocessor or postprocessor not enable")

        return processed_input_output

    def check_and_do_session_change(self, connection_copy, detection_time, conv_rules_original_format=None,
                                    async_conv_rules=None):
        '''
        Method to check if a executed rule triggers a change in the session ID used by a connection,
        and do it if applicable. Expected session update information within the rule
            SessionUpdate {
                Enable
                # For session value
                MemoryVariable (first to be used)
                AutogeneratedValue (second to be used)
                FixedValue (third to be used)
            }
        Async rules has the following format => Tuple (ID triggering rule, delay, rule to execute)
        '''
        moment_check =\
            self.connection_register.session_update_when_detected == detection_time  # expected time to do it?
        session_update_check = \
            self.connection_register.session_update_flag and moment_check

        if session_update_check:
            logger.info(
                f"Session update functionality enable, checking rules for the connection:{connection_copy.id}")
            if conv_rules_original_format is not None:
                for rule in conv_rules_original_format:
                    connection_copy = self.evaluate_rule_for_session_id_change(
                        rule, connection_copy)

            elif session_update_check and async_conv_rules is not None:
                for _, _, rule in async_conv_rules.values():
                    connection_copy = self.evaluate_rule_for_session_id_change(
                        rule, connection_copy)

        return connection_copy

    # =========================================================================================
    # Detecting/Input rules methods
    # =========================================================================================
    def apply_encoding_to_input(self, ext_input):
        '''
        Method to apply the configured encoding to a given input
        '''
        if ext_input is not None:
            try:
                ext_input = ext_input.decode(
                    self.cnv_rules.ExtOperation.Encoding)
            except (UnicodeDecodeError, AttributeError):
                ext_input = str(ext_input)
                logger.warning(
                    "Exception applying encoding to external input, passing it as raw string. " +
                    f"Received input encoded in b64: {base64.b64encode(ext_input.encode())}")
        return ext_input

    def greetings_message_check(self, connection_copy):
        greetings_rule = None
        # If greetings message is not already sent, prepare to do it
        if connection_copy.greetings_sent is not None and not connection_copy.greetings_sent:
            # You can mark it as completed because it was not marked before
            greetings_flag = self.connection_register.mark_greetings_flag_as_completed(
                connection_copy.id)

            if greetings_flag:
                greetings_rule = self.cnv_rules.Conversation.Greetings

        return greetings_rule

    def send_greetings_message(self, connection_copy, socket_conn):
        '''
        Method to send the greetings message directly
        '''
        done = False
        conn_broken = False
        greetings_rule = self.greetings_message_check(connection_copy)

        if greetings_rule is not None:
            done, conn_broken = self.send_basic_rule_message(
                greetings_rule, connection_copy, socket_conn)
            if conn_broken:
                self.close_broken_connection(connection_copy, False)

        return done, conn_broken

    def detect_conversation_rules(self, connection_copy, recv_data):
        '''
        Method to detect what conversation rules are applicable
        according to the regex and the memory conditions (if any).
        It also returned the captured data for the application rules
        '''
        default_rule = None
        empty_rule = None
        captured_data = None

        # get a copy of the multi external cloud memory, global memory and the connection memory
        multi_ext_conn_mem, global_mem, conn_mem = self.get_memories_copy(
            connection_copy.id)

        potential_empty_string = re.sub('\n', '', recv_data)
        if recv_data is not None and len(potential_empty_string) > 0:
            # detect the applicables rules
            regex_conv_rules, captured_data = conv_mod.detect_applicable_rules_using_regex(
                self.cnv_rules,
                multi_ext_conn_mem,
                global_mem,
                conn_mem,
                recv_data,
                self.number_rule_checker_subworkers)
            # If no conversation rules are detected
            if not len(regex_conv_rules) > 0:
                default_rule = self.cnv_rules.Conversation.Default
                logger.info(
                    f"No conversation rules applicable in the connnection:{connection_copy.id}, " +
                    "then the 'default' rule will be executed (if enabled)")
        else:
            regex_conv_rules = set()
            empty_rule = self.cnv_rules.Conversation.Empty
            logger.info(f"Not input for the connection:{connection_copy.id}, so no conversation " +
                        "rules applicable, except the 'empty' rule")

        return regex_conv_rules, default_rule, empty_rule, captured_data

    def detect_beginning_async_rules_from_a_set_of_rules(self, rule_set, async_rules):
        '''
        Method to detect beginning async rules given a set of rules.
        '''
        for rule in rule_set:
            if conv_mod.check_async_beginning_rule(rule):
                async_rules[rule.Id] = (
                    None, rule.BeginningAsyncDelay, rule)
                logger.info("Detected new async rule to be executed at " +
                            "the beginning of the connection. " +
                            f"ID:{rule.Id}")

        return async_rules

    def detect_async_rules_for_beginning(self, connection_id):
        '''
        Method to detect the async rules that are triggered
        from the beginning of the connection/session.
        The async rules are saved following the following structure:
        Tuple (None, delay, rule to execute)
        '''
        # variable to return
        async_rules = dict()
        async_rules = self.detect_beginning_async_rules_from_a_set_of_rules(
            self.cnv_rules.Conversation.CustomRules.Rules,
            async_rules)

        if self.cnv_rules.Conversation.CustomRules.Groups is not None:
            
            # Get copy of memory variables
            multi_ext_conn_mem, global_mem, conn_mem = self.get_memories_copy(
                connection_id)

            for group in self.cnv_rules.Conversation.CustomRules.Groups:
                if (conv_mod.is_group_applicable(
                        group, multi_ext_conn_mem, global_mem, conn_mem)):
                    async_rules = self.detect_beginning_async_rules_from_a_set_of_rules(
                        group.Rules,
                        async_rules)

        return async_rules

    def get_async_rules_given_a_trigger_information_from_a_set_of_rules(
            self, triggering_rule, rules_to_check,
            rule_id_list, async_rule_tuple_list):
        '''
        Auxiliary method to get the async applicable rules given a trigger
        rule information an a set of rules
        '''

        if triggering_rule.RuleID > 0:
            # Find the rule with the ID mentioned in the rule trigger
            for rule in rules_to_check:
                if triggering_rule.RuleID == rule.Id:
                    # Format: rule_to_execute_async_ID: Tuple (Rule ID trigging rule,
                    # delay, rule to execute)
                    rule_id_list.append(rule.Id)
                    async_rule_tuple_list.append(
                        (triggering_rule.RuleID, triggering_rule.Delay, rule))
                    logger.info(
                        f"Detected async rule with ID:{triggering_rule.RuleID}")
                    break

        return rule_id_list, async_rule_tuple_list

    def get_async_rules_given_a_trigger_information(self, trigger_info, connection_id):
        '''
        Auxiliary function to get the async applicable rules given a trigger rule information
        '''
        rule_id_list = list()
        async_rule_tuple_list = list()

        # get copy of memory variables
        multi_ext_conn_mem, global_mem, conn_mem = self.get_memories_copy(
            connection_id)

        if trigger_info is not None:
            for triggering_rule in trigger_info:

                # check non-grouped rules
                rule_id_list, async_rule_tuple_list =\
                    self.get_async_rules_given_a_trigger_information_from_a_set_of_rules(
                        triggering_rule, self.cnv_rules.Conversation.CustomRules.Rules,
                        rule_id_list, async_rule_tuple_list)

                # check rules in groups (if group memory conditions are ok)
                if self.cnv_rules.Conversation.CustomRules.Groups is not None:
                    for group in self.cnv_rules.Conversation.CustomRules.Groups:
                        if (conv_mod.is_group_applicable(
                                group, multi_ext_conn_mem, global_mem, conn_mem)):

                            rule_id_list, async_rule_tuple_list =\
                                self.get_async_rules_given_a_trigger_information_from_a_set_of_rules(
                                    triggering_rule, group.Rules,
                                    rule_id_list, async_rule_tuple_list)

        return rule_id_list, async_rule_tuple_list

    def add_async_rules_to_execute(self, async_rules, rule_id_list, async_rule_tuple_list):
        '''
        Auxiliary method to add new async rules to execute in the current
        list of async rules detected
        '''
        if (len(rule_id_list) > 0) and (len(async_rule_tuple_list) > 0) and (
                len(rule_id_list) == len(async_rule_tuple_list)):
            for idx, rule_id in enumerate(rule_id_list):
                async_rules[rule_id] = async_rule_tuple_list[idx]

        return async_rules

    def get_async_rules_for_async_switch(self, async_rules, connection_id, executed_rule):
        '''
        Auxiliary method to implement the logic of the switch of async rules that
        could be present in any executed rule
        '''
        any_condition_applicable_flag = False

        # get a copy of the multi external cloud memory, global memory and
        # the connection memory
        multi_ext_conn_mem, global_mem, conn_mem = self.get_memories_copy(
            connection_id)

        # Itereate over all 'case' or switch options
        for switch_option in executed_rule.AsyncSwitch.SwitchAsyncOptions:

            # check memory conditions
            if conv_mod.check_memory_conditions(switch_option.Conditions,
                                                multi_ext_conn_mem,
                                                global_mem,
                                                conn_mem):
                any_condition_applicable_flag = True

                # Get the rules to execute asynchronously
                rule_id_list, async_rule_tuple_list =\
                    self.get_async_rules_given_a_trigger_information(
                        switch_option.ConditionalRules, connection_id)

                # Add them to the 'list' (dict)
                async_rules = self.add_async_rules_to_execute(
                    async_rules, rule_id_list, async_rule_tuple_list)

                # stop the iteration accross switch options
                break

        if (not any_condition_applicable_flag and
                executed_rule.AsyncSwitch.DefaultAsyncRule is not None):
            # Get the rules to execute asynchronously
            rule_id_list, async_rule_tuple_list =\
                self.get_async_rules_given_a_trigger_information(
                    executed_rule.AsyncSwitch.DefaultAsyncRule, connection_id)

            # Add them to the 'list' (dict)
            async_rules = self.add_async_rules_to_execute(
                async_rules, rule_id_list, async_rule_tuple_list)

        return async_rules

    def detect_async_rules(self, executed_conv_rules, connection_id):
        '''
        Method to dected the async rules that are triggered by the executed rules.
        The async rules are saved following the following structure:
        Tuple (ID triggering rule, delay, rule to execute)
        '''
        # variable to return
        async_rules = dict()

        # For each executed rule with a valid rule trigger (not zero)
        for executed_rule in executed_conv_rules:

            # Get the rules to execute asynchronously (always)
            rule_id_list, async_rule_tuple_list =\
                self.get_async_rules_given_a_trigger_information(
                    executed_rule.Trigger, connection_id)

            # Add them to the 'list' (dict)
            async_rules = self.add_async_rules_to_execute(
                async_rules, rule_id_list, async_rule_tuple_list)

            # Get the rules to execute asynchronously (switch case)
            if (executed_rule.AsyncSwitch is not None) and (
                    executed_rule.AsyncSwitch.SwitchAsyncOptions is not None):

                async_rules = self.get_async_rules_for_async_switch(
                    async_rules, connection_id, executed_rule)

            # Review if there is any async loop to execute
            if ((executed_rule.AsyncLoop is not None) and
                (executed_rule.AsyncLoop.ConditionalRules is not None and
                 len(executed_rule.AsyncLoop.ConditionalRules) > 0)):

                async_rule_tuple_list_loop = list()
                rule_id_list = list()

                # Get the rules to execute in the loop
                for triggering_rule in executed_rule.AsyncLoop.ConditionalRules:
                    rule_id_list, async_rule_tuple_list_loop = self.get_async_rules_given_a_trigger_information_from_a_set_of_rules(
                        triggering_rule,
                        self.cnv_rules.Conversation.CustomRules.Rules,
                        rule_id_list,
                        async_rule_tuple_list_loop)

                # Add the async loop (if applies)
                self.todo_list.add_async_loop(connection_id,
                                              executed_rule.AsyncLoop,
                                              executed_rule.Id,
                                              async_rule_tuple_list_loop)

            # Detect if there is any fork action to do (spawn a new external connector)
            if executed_rule.Fork is not None and interlanguage_bool_check(executed_rule.Fork.Enable):
                
                # Determine how many instances should start
                if executed_rule.Fork.NumberOfInstances > 1:
                    number_instances = executed_rule.Fork.NumberOfInstances
                else:
                     number_instances = 1
                    
                    # Start as many instances as required
                for i in range(number_instances):
                    subprocess.run(['python',
                                    'start.py',
                                    BANNER_COMMAND_LINE_ARGS_KEY_SHORT,
                                    CONFIG_COMMAND_LINE_ARGS_KEY_SHORT, executed_rule.Fork.Config,
                                    ID_COMMAND_LINE_ARGS_KEY_SHORT, executed_rule.Fork.ExtConnID,
                                    PASS_COMMAND_LINE_ARGS_KEY_SHORT, executed_rule.Fork.Secret], 
                                   shell=False)
                    logger.warning(f"New external connector created! {i+1}/{number_instances}")

        return async_rules

    # =========================================================================================
    # Sending data methods
    # =========================================================================================

    def postprocessor_step(self, response, connection_copy):
        '''
        Function for the part of the execution of a postprocessor custom function execution
        '''
        # Execute post processor function
        processed_input_output = self.check_and_execute_custom_function_pre_post_processor(
            response, connection_copy, False)

        # Encode the answer using the right encoding
        data_bytes = processed_input_output.encode(
            self.cnv_rules.ExtOperation.Encoding)

        return data_bytes

    def send_basic_rule_message(self, basic_rule, connection_copy, socket_conn):
        '''
        Method to send the greetings message
        '''
        # variable to returnsend_basic_rule_message
        success = False
        conn_broken = False
        if interlanguage_bool_check(basic_rule.Enable):
            # If this field is not empty
            if len(basic_rule.Value) > 0:
                # get a copy of the global memory and the connection memory
                multi_ext_conn_mem, global_mem, conn_mem = self.get_memories_copy(
                    connection_copy.id)
                response = conv_mod.prepare_reply(
                    basic_rule.Value, basic_rule.B64Flag,
                    multi_ext_conn_mem, global_mem, conn_mem,
                    connection_copy.session_key, connection_copy.session_value,
                    connection_copy.id, connection_copy.ip, connection_copy.port)
                logger.info(
                    f"Sending the '{basic_rule.Name}' " +
                    f"message in the connection:{connection_copy.id} " +
                    f"to the IP:{connection_copy.ip}")

                data_bytes = self.postprocessor_step(response, connection_copy)

                success, conn_broken = self.ext_conn_controller.send_data(
                    data_bytes, connection_copy.ip, connection_copy.port, socket_conn)
            else:
                success = True
                logger.info(f"The '{basic_rule.Name}' message in " +
                            f"the connection:{connection_copy.id} " +
                            "is not sent since the field 'Value' is empty, " +
                            "so nothing to send => 'Rule executed' then")
        else:
            logger.info(
                f"The '{basic_rule.Name}' message is not sent since this rule is disable " +
                "in the conversation rules")

        return success, conn_broken

    def send_response_according_conv_rule(self, rule, multi_ext_conn_mem,
                                          global_mem, conn_mem,
                                          connection_copy, socket_conn):
        '''
        Method to send the response of a conversation rule
        '''
        result = False
        conn_broken = False
        if len(rule.Response) > 0:

            # Prepare the reply
            response = conv_mod.prepare_reply(
                rule.Response, rule.ResponseBase64Flag, multi_ext_conn_mem,
                global_mem, conn_mem,
                connection_copy.session_key,
                connection_copy.session_value,
                connection_copy.id, connection_copy.ip, connection_copy.port)

            data_bytes = self.postprocessor_step(response, connection_copy)

            # Send the reply
            result, conn_broken = self.ext_conn_controller.send_data(
                data_bytes, connection_copy.ip, connection_copy.port, socket_conn)
        else:
            result = True  # Nothing to send ==> rule 'execution' is successful
            logger.info(
                f"The conversation rule:{rule.Id} has no response to send")

        return result, conn_broken

    def send_rules_messages(self, connection_copy, socket_conn, conv_rules):
        '''
        Method to send sync messages according to the conversation rules applicable
        '''
        # Varibale to return
        executed_conv_rules = list()
        conn_broken = False
        # Get memories copy
        multi_ext_conn_mem, global_mem, conn_mem = self.get_memories_copy(
            connection_copy.id)

        for rule in conv_rules:
            result, conn_broken = self.send_response_according_conv_rule(
                rule, multi_ext_conn_mem, global_mem, conn_mem, connection_copy, socket_conn)
            if result:
                executed_conv_rules.append(rule)
                logger.info(
                    f"Conversation rule:{rule.Id} executed successfully")

            elif conn_broken:
                self.close_broken_connection(connection_copy, False)
                break
            else:
                logger.info(
                    f"Conversation rule:{rule.Id} not executed, but connection is not broken")

        return executed_conv_rules, conn_broken

    # =========================================================================================
    # Management methods
    # =========================================================================================
    def register_async_rules_for_a_connection(self, async_rules, conn_id):
        '''
        Method to add the async rules in the ToDo List for being sent later
        '''
        if async_rules is not None:
            for rule_tuple in async_rules.values():
                self.todo_list.add_new_todo(conn_id, rule_tuple)

    def close_connection(self, connection_copy, socket_conn):
        '''
        Method to close logically and physically a connection. 
        '''
        logger.info(
            f"Closing connection:{connection_copy.id}...")
        success, conn_broken = self.send_basic_rule_message(
            self.cnv_rules.Conversation.Ending, connection_copy, socket_conn)
        logger.info(
            f"Was the ending rule sent sucessfully? {success}. Is the conenction broken? {conn_broken}")
        # UDP server not encrypted
        if self.ext_conn_controller.udp_protocol and not (self.ext_conn_controller.client_mode or
                                                          self.ext_conn_controller.encrypted):
            # Only a logical close since the only socket in use is the listening one.
            self.connection_register.end_connection(connection_copy.id)

        else:  # TCP or UDP Client or UDP + DTLS
            if conn_broken:
                self.close_broken_connection(connection_copy, True)
            else:
                self.ext_conn_controller.close_socket(socket_conn)
                self.connection_register.end_connection(connection_copy.id)

    def update_conn_register(self, connection_copy, executed_conv_rules, socket_conn):
        '''
        Method to update the connection register according to the rules executed
        '''
        end_connection = False
        for executed_rule in executed_conv_rules:
            # Check if any executed was an ending
            if interlanguage_bool_check(executed_rule.EndingRule):
                end_connection |= True
                logger.info(
                    f"Ending rule detected among the executed rules. Rule ID:{executed_rule.Id}")

        if end_connection:
            self.close_connection(connection_copy, socket_conn)
        elif len(executed_conv_rules) > 0:
            self.connection_register.touch_connection(connection_copy.id)

        return end_connection

    def update_act_register(
            self, new_conn_flag=None, tcp_dtls_conn_ready_flag=None, ip=None, port=None,
            connection_id=None, greetings_rule=None, executed_regex_conv_rules=None,
            default_rule=None, empty_rule=None, detected_async_rules=None, captured_data=None,
            end_connection=None, ext_input=None, async_activity_flag=None, executed_async_rules=None,
            list_connections_timed_out=None, conn_broken=None):
        '''
        Method to update the activity register according to the result of the operation loop
        '''
        multi_ext_conn_mem, global_mem, conns_mem =\
            self.connection_register.get_copy_of_memory_to_be_reported(
                connection_id)

        if new_conn_flag:
            hash_conversation_rules_used = self.hash_conversation_rules_used
        else:
            hash_conversation_rules_used = None

        self.activity_register.add_activity(
            new_conn_flag, tcp_dtls_conn_ready_flag, ip, port, connection_id, greetings_rule,
            executed_regex_conv_rules, default_rule, empty_rule, detected_async_rules,
            captured_data, end_connection, ext_input, async_activity_flag, executed_async_rules,
            list_connections_timed_out, self.cnv_rules.ExtOperation.Encoding, conn_broken,
            multi_ext_conn_mem, global_mem, conns_mem, self.cnv_rules.Name,
            hash_conversation_rules_used)

    def close_broken_connection(self, connection_copy, async_activity_flag):
        '''
        Method to logically close a broken connection
        '''
        logger.warn("Logical 'close' of a broken connection!")
        self.connection_register.end_connection(connection_copy.id)
        self.update_act_register(
            ip=connection_copy.ip,
            port=connection_copy.port,
            connection_id=connection_copy.id,
            end_connection=True,
            async_activity_flag=async_activity_flag,
            conn_broken=True)

    def check_and_close_tcp_or_dtls_socket_but_not_connection(self, connection_copy):
        '''
        Method to check (if it is applicable) and close a socket of a connection after answering to 
        a given input (sync or a set of async rules). This method do not close the connection
        '''
        if ((self.ext_conn_controller.udp_protocol and
             self.ext_conn_controller.encrypted) or
                not self.ext_conn_controller.udp_protocol) and (
                    self.connection_register.close_tcp or
                    self.connection_register.enable_rule_triggered_close_socket):
            if connection_copy.connection_socket is not None:
                logger.info(
                    f"TCP/DTLS socket of the connection {connection_copy.id} " +
                    "is going to be closed because sockets should be closed once " +
                    "the answer/s is/are already provided given an input")
                self.ext_conn_controller.close_socket(
                    connection_copy.connection_socket)
            else:
                logger.warn(
                    f"TCP/DTLS socket of a the connection {connection_copy.id} " +
                    "is None at the time to be closed!")

    def check_and_enable_sync_done_async_in_progress_flag(self, connection_copy):
        '''
        Method to check (if it is applicable) and enable the flag 'sync_done_async_in_progress'
        '''
        if ((self.ext_conn_controller.udp_protocol and self.ext_conn_controller.encrypted) or
                not self.ext_conn_controller.udp_protocol) and (
                    self.connection_register.close_tcp or
                    self.connection_register.enable_rule_triggered_close_socket):
            self.connection_register.enable_sync_done_async_in_progress_flag_of_a_connection(
                connection_copy.id)

    def tcp_or_dtls_client_reconnect(self, connection_copy,
                                     time_between_client_socket_close_connect):
        '''
        Method to reconnect a TCP/DTLS client in the scenanario tcp 
        socket close after answering
        '''
        logger.info(
            f"Reconnecting the client connection {connection_copy.id}")
        # Mark the connection as 'reconnecting'
        self.connection_register.mark_reconnecting_connection(
            connection_copy.id)
        # Close the previous socket
        self.check_and_close_tcp_or_dtls_socket_but_not_connection(
            connection_copy)
        # sleeping before reconnecting
        time.sleep(time_between_client_socket_close_connect)

        # Now, reconnect
        success, new_socket = self.ext_conn_controller.tcp_or_dtls_new_client_socket(
            connection_copy.client_socket_id, self.cleaning_register)
        if success:
            self.connection_register.unmark_reconnecting_connection(
                connection_copy.id)
        else:
            self.close_broken_connection(connection_copy, False)

        connection_copy =\
            self.connection_register.update_connection_socket_and_port_of_a_connection(
                connection_copy.id, new_socket)

        return success, connection_copy

    def check_and_wait_for_tcp_or_dtls_client_reconnection(self, connection_copy,
                                                           waiting_time_for_reconnection):
        '''
        Method to wait for a tcp or ddtls client reconnection
        '''
        reconnecting_status_flag = True
        status = connection_copy.status

        while reconnecting_status_flag:
            status = self.connection_register.check_connection_status(
                connection_copy.id)
            reconnecting_status_flag = status == connection.ConnectionStatus.RECONNECTING
            if reconnecting_status_flag:
                logger.info(
                    f"Connection{connection_copy.id} is 'RECONNECTING', waiting before going on")
                time.sleep(waiting_time_for_reconnection)

        return status

    def check_exec_rules_for_closing(self, executed_regex_conv_rules):
        '''
        Method for checking a set of executed rules, to see if the connection should be closed
        but not ended (logic connection still alive, but socket should be closed). This is only applicable
        for TCP or DTLS connections when the mode of closing after answering is not enable
        '''
        close_connection = False
        if self.connection_register.enable_rule_triggered_close_socket and\
            executed_regex_conv_rules is not None and\
                len(executed_regex_conv_rules) > 0:
            for rule in executed_regex_conv_rules:
                close_connection |= interlanguage_bool_check(rule.ClosingConn)

        return close_connection

    def check_exec_rules_for_reconnection(self, executed_regex_conv_rules):
        '''
        Method for checking a set of executed rules, to see if the connection should be closed
        but not ended (logic connection still alive, but socket should be closed). This is only applicable
        for TCP or DTLS connections when the mode of closing after answering is not enable
        '''
        reconnect = False
        if self.connection_register.enable_rule_triggered_close_socket:
            for rule in executed_regex_conv_rules:
                reconnect |= interlanguage_bool_check(
                    rule.ReconnectBeforeRuleExecution)

        return reconnect

    # =========================================================================================
    # Async tasks methods
    # =========================================================================================

    def send_timeouts_messages(self, conns_timed_out):
        '''
        Method to send the timeouts messages 
        '''
        for conn_copy in conns_timed_out:
            socket_conn = conn_copy.get_connection_socket()
            if socket_conn is not None:
                success, conn_broken = self.send_basic_rule_message(
                    self.cnv_rules.Conversation.Timeout, conn_copy, socket_conn)
                logger.info(
                    f"Was the timout rule sent sucessfully? {success}. " +
                    f"Is the conenction broken? {conn_broken}")
                if conn_broken:
                    self.close_broken_connection(conn_copy, True)
                else:
                    self.close_connection(conn_copy, socket_conn)
            else:
                logger.info(
                    f"No connection socket for the timed out connection {conn_copy.id}, " +
                    "so, no timeout message to send")

    def execute_specific_async_conv_rule(self, todo, connection_copy, executed_async_rules,
                                         connections_used_copies):
        '''
        Method to execute a given async conversation rule rule
        '''
        logger.info(f"Executing the rule {todo.rule_to_execute.Id} asynchronously, " +
                    f"triggered by the rule {todo.triggering_rule} in the connection: {connection_copy.id}")

        close_after_answering_mode = (
            (self.ext_conn_controller.udp_protocol and self.ext_conn_controller.encrypted) or
            not self.ext_conn_controller.udp_protocol) and self.connection_register.close_tcp

        enable_rule_triggered_close_socket = self.connection_register.enable_rule_triggered_close_socket
        rule_triggered_reconnection = enable_rule_triggered_close_socket and interlanguage_bool_check(
            todo.rule_to_execute.ReconnectBeforeRuleExecution)

        client_and_close_after_answer_mode = (
            close_after_answering_mode
            or rule_triggered_reconnection) and self.connection_register.client_mode
        success_reconnection = False

        # TCP/TLS CLIENT & CLOSE AFTER ANSWER MODE: At this moment, the socket connection should
        # be closed (server already answered)
        if client_and_close_after_answer_mode and (
                connection_copy.status == connection.ConnectionStatus.OPEN):
            success_reconnection, connection_copy = self.tcp_or_dtls_client_reconnect(
                connection_copy,
                self.ext_conn_controller.time_between_client_socket_close_connect)

        if not client_and_close_after_answer_mode or (
                client_and_close_after_answer_mode and success_reconnection):
            # Get again the memories copy (potentially modified according to the executed async rules)
            multi_ext_conn_mem, global_mem, conn_mem = self.get_memories_copy(
                connection_copy.id)
            # Send the message of the conversation rule
            result, conn_broken = self.send_response_according_conv_rule(
                todo.rule_to_execute, multi_ext_conn_mem, global_mem, conn_mem, connection_copy,
                connection_copy.get_connection_socket())
            if result:
                # Update memory (if apply), only for the rule executed right now.
                self.check_and_do_memory_updates(
                    connection_copy, detection_time=False,
                    conv_rules_original_format=[todo.rule_to_execute])
                # Execute builtin memory operations (if apply), only for the rule executed right now.
                self.check_and_execute_mem_operations(
                    connection_copy, detection_time=False,
                    conv_rules_original_format=[
                        todo.rule_to_execute],
                    custom_functions_flag=False)
                # Execute custom functions(custom memory operations) (if apply), only for the rule executed right now.
                self.check_and_execute_mem_operations(
                    connection_copy, detection_time=False,
                    conv_rules_original_format=[
                        todo.rule_to_execute],
                    custom_functions_flag=True)
                # Check and do the session id change if applicable
                connection_copy = self.check_and_do_session_change(
                    connection_copy, detection_time=False,
                    conv_rules_original_format=[todo.rule_to_execute])
                # Add the executed async rule in list of the corresponding connection id
                if connection_copy.id in executed_async_rules:
                    executed_async_rules[connection_copy.id] = [
                        *executed_async_rules[connection_copy.id], todo.rule_to_execute]
                else:
                    executed_async_rules[connection_copy.id] = [
                        todo.rule_to_execute]
                # Save the connection copy for later use
                connections_used_copies[connection_copy.id] = connection_copy
            elif conn_broken:
                self.close_broken_connection(connection_copy, True)

        return executed_async_rules, connections_used_copies

    def execute_async_rules(self, todos_to_do, waiting_time_for_reconnection):
        '''
        Method to send the asynchronous conversation rules. ToDo fields: id, execution_time, 
        connection_id, rule_to_execute,triggering_rule
        '''
        # variables to return
        # {connection_id: [List of executed async rules], ... }
        executed_async_rules = dict()
        # {connection_id: conection_copy_object, ... }
        connections_used_copies = dict()
        for todo in todos_to_do:
            connection_copy = self.connection_register.get_connection_copy(
                todo.connection_id)

            if connection_copy is not None:
                # Wait if the connection is doing a reconnection
                status = self.check_and_wait_for_tcp_or_dtls_client_reconnection(
                    connection_copy,
                    waiting_time_for_reconnection)
                if status == connection.ConnectionStatus.OPEN:
                    # Get memories copy
                    multi_ext_conn_mem, global_mem, conn_mem = self.get_memories_copy(
                        connection_copy.id)
                    # Check memory conditions of the async rule
                    if conv_mod.check_memory_and_rule(todo.rule_to_execute, multi_ext_conn_mem, global_mem, conn_mem):
                        executed_async_rules, connections_used_copies = self.execute_specific_async_conv_rule(
                            todo, connection_copy,
                            executed_async_rules,
                            connections_used_copies)
                    else:
                        logger.info(f"The async rule:{todo.rule_to_execute.Id}, cannot be executed asynchronously, " +
                                    "it does not match the corresponding memory conditions")
                else:
                    logger.warning(f"Connection:{connection_copy.id} not 'OPEN' at the time of executing " +
                                   f"an async task. ToDo ID:{todo.id}, async rule:{todo.rule_to_execute.Id} " +
                                   f"triggered by the rule:{todo.triggering_rule}")
            else:
                logger.warning(f"The async rule to execute:{todo.rule_to_execute.Id} triggered by the rule:" +
                               f"{todo.triggering_rule} was not possible to execute since no connection has " +
                               "been found (ID not found)")
        return executed_async_rules, connections_used_copies
