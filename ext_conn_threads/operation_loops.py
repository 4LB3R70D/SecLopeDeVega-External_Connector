"""
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega external connector
=================================================
Module: operation_loops.py
Author: Alberto Dominguez 

This module contains the operation loops of the operation workers:
    - udp client operation loop
    - tcp client operation loop
    - udp server operation loop
    - tcp server operation loop 
    - async tasks operation loop
"""
import logging
import selectors
import time

import operation_variables.request_processing_list as req_proc_list
from ext_conn_comms.ext_comm_controller import CLOSED_SOCKET
from logic_modules.conversation_module import check_memory_and_rule
from operation_variables.connection import ConnectionStatus
from utils.interoperability_py_go import interlanguage_bool_check

# logger
logger = logging.getLogger(__name__)

# Constants for the addr tuple
ADDR_IP = 0
ADDR_PORT = 1
CLIENT_SOCKET_ID = 2

# Other constants
WAITING_TIME_ASYNC_TASK_IN_PROGRESS_WHEN_CLOSING_TCP_OR_DTLS_CONN = 0.25  # seconds

# ==========================================================================================
# AUXILIARY FUNCTIONS
# ==========================================================================================


def execute_sync_rules(op_wrker, default_rule, empty_rule, regex_conv_rules, connection_copy,
                       socket_conn):
    '''
    Auxiliary function to send responses given a set of synchronous rules and it returns the 
    asynchronous rules that are triggered by them (if any)
    '''
    async_rules = dict()
    # Regex rules can be executed if applicable
    if len(regex_conv_rules) > 0:
        executed_regex_conv_rules, conn_broken = op_wrker.send_rules_messages(
            connection_copy,
            socket_conn,
            regex_conv_rules)
        # if there are executed rules...
        if len(executed_regex_conv_rules) > 0:
            async_rules_regex = op_wrker.detect_async_rules(
                executed_regex_conv_rules, connection_copy.id)
            async_rules = {**async_rules, **async_rules_regex}
        else:
            async_rules = op_wrker.detect_async_rules(
                executed_regex_conv_rules, connection_copy.id)

    # Default rule applicable
    elif default_rule is not None:
        _, conn_broken = op_wrker.send_basic_rule_message(
            default_rule, connection_copy, socket_conn)
        executed_regex_conv_rules = None
        async_rules = None

    else:
        # Empty rule applicable
        _, conn_broken = op_wrker.send_basic_rule_message(
            empty_rule, connection_copy, socket_conn)
        executed_regex_conv_rules = None
        async_rules = None

    return executed_regex_conv_rules, async_rules, conn_broken


def end_async_rules_processing_for_closing_tcp_or_dtls_conn_after_answer(connection_copy, op_wrker,
                                                                         rule_triggered_close_socket):
    '''
    This functions mark as 'complete' the execution of async rules in a close tcp connection 
    after answering scenario 
    '''
    close_after_answering_mode = (
        (op_wrker.ext_conn_controller.udp_protocol and op_wrker.ext_conn_controller.encrypted) or
        not op_wrker.ext_conn_controller.udp_protocol) and op_wrker.connection_register.close_tcp

    close_after_answer_due_to_rule = op_wrker.connection_register.enable_rule_triggered_close_socket and\
        rule_triggered_close_socket

    if (close_after_answering_mode or
            close_after_answer_due_to_rule) and not op_wrker.connection_register.client_mode:
        op_wrker.check_and_close_tcp_or_dtls_socket_but_not_connection(
            connection_copy)

    op_wrker.connection_register.disable_sync_done_async_in_progress_flag_of_a_connection(
        connection_copy.id)

    if connection_copy.client_mode:
        addr = (connection_copy.ip, connection_copy.port,
                connection_copy.client_socket_id)
    else:
        addr = (connection_copy.ip, connection_copy.port)
    req_proc_list.remove_request_from_processing_list_for_managing_conn_closing_after_answering(
        addr)


def filter_async_rules_for_closing_tcp_or_dtls_conn_after_answer(op_wrker, connection_copy, async_rules):
    '''
    This function removes those async rules that are not applicable for memory conditions in 
    a close tcp connection after answering scenario 
    '''
    multi_ext_conn_mem, global_mem, conn_mem = op_wrker.get_memories_copy(
        connection_copy.id)
    # Check memory conditions of the async rules to be removed before adding them in the ToDo list
    # async_rules[rule.Id] = (executed_rule.Id, rule.Delay, rule)
    for rule_id_key, (_, _, rule) in async_rules.copy().items():
        # async_rules[rule.Id] = (executed_rule.Id, rule.Delay, rule)
        if not check_memory_and_rule(rule, multi_ext_conn_mem, global_mem, conn_mem):
            async_rules.pop(rule_id_key)

    return async_rules


def check_and_update_memory_and_session_and_do_memory_operations(
        op_wrker,
        connection_copy,
        external_input=None,
        detection_time=False,
        regex_conv_rules=None,
        captured_data=None,
        async_conv_rules=None):
    '''
    Function for the operations to check and update the memory variables and the session, as well as
    executing memory olperations and custom functions
    '''
    # check and do the update memory (if applicable), only for those rules to be executed right now
    op_wrker.check_and_do_memory_updates(
        connection_copy, detection_time,
        conv_rules_original_format=regex_conv_rules,
        captured_data=captured_data,
        async_conv_rules=async_conv_rules)
    # check and execute builtin memory operations if applicable
    op_wrker.check_and_execute_mem_operations(
        connection_copy, detection_time,
        conv_rules_original_format=regex_conv_rules,
        external_input=external_input,
        custom_functions_flag=False,
        async_conv_rules=async_conv_rules)
    # check and execute custom functions (custom memory operations) if applicable
    op_wrker.check_and_execute_mem_operations(
        connection_copy, detection_time,
        conv_rules_original_format=regex_conv_rules,
        external_input=external_input,
        custom_functions_flag=True,
        async_conv_rules=async_conv_rules)
    # check and do the session id change if applicable
    connection_copy = op_wrker.check_and_do_session_change(
        connection_copy,
        conv_rules_original_format=regex_conv_rules,
        detection_time=detection_time,
        async_conv_rules=async_conv_rules)
    return connection_copy


def register_async_rules(op_wrker, async_rules, connection_copy, external_input=None):
    '''
    Auxiliary function to register async rules in the ToDo list
    '''
    if async_rules is not None and len(async_rules) > 0:
        register_flag = True

        # In case of being in a close tcp/dtls connection after answering scenario
        if ((op_wrker.ext_conn_controller.udp_protocol and op_wrker.ext_conn_controller.encrypted) or
            not op_wrker.ext_conn_controller.udp_protocol) and (
                op_wrker.connection_register.close_tcp or
                op_wrker.connection_register.enable_rule_triggered_close_socket):

            async_rules = filter_async_rules_for_closing_tcp_or_dtls_conn_after_answer(
                op_wrker,
                connection_copy,
                async_rules)
            if len(async_rules) == 0:
                register_flag = False
                end_async_rules_processing_for_closing_tcp_or_dtls_conn_after_answer(
                    connection_copy, op_wrker, False)

        if register_flag:
            op_wrker.register_async_rules_for_a_connection(
                async_rules, connection_copy.id)
            connection_copy = check_and_update_memory_and_session_and_do_memory_operations(
                op_wrker,
                connection_copy,
                external_input=external_input,
                detection_time=True,
                async_conv_rules=async_rules)
    else:
        logger.info("No async rules to register")

    return connection_copy


def check_sync_rules_for_something_to_send(regex_conv_rules):
    '''
    Function to check if a set of conversation rules has something to send for tcp client case
    where the connection is closed after answering
    '''
    something_to_send = False

    if len(regex_conv_rules) > 0:
        for rule in regex_conv_rules:
            if len(rule.Response) > 0:
                something_to_send = something_to_send or True

    return something_to_send


def do_tcp_or_dtls_socket_reconnection(op_wrker, connection_copy):
    '''
    Function to do a socket reconnection for tcp or dtls modes
    '''
    success_reconnection, connection_copy = op_wrker.tcp_or_dtls_client_reconnect(
        connection_copy,
        op_wrker.ext_conn_controller.time_between_client_socket_close_connect)
    socket_conn = connection_copy.connection_socket

    return success_reconnection, connection_copy, socket_conn


def wait_for_tcp_or_dtls_reconnection(op_wrker, connection_copy):
    '''
    Function to wait for a reconnection (if needed)
    '''
    # Wait for the flag for controlling the sync rules execution in the context of
    # closing sockets after answering in TCP or DTLS (when the value is false, it can go on)
    async_rules_in_progress = True
    while async_rules_in_progress:
        async_rules_in_progress = op_wrker.\
            connection_register.check_sync_done_async_in_progress_flag_of_a_connection(
                connection_copy.id)
        if async_rules_in_progress:
            time.sleep(
                WAITING_TIME_ASYNC_TASK_IN_PROGRESS_WHEN_CLOSING_TCP_OR_DTLS_CONN)

    # After, wait if the connection is doing a reconnection
    status = op_wrker.\
        check_and_wait_for_tcp_or_dtls_client_reconnection(
            connection_copy,
            WAITING_TIME_ASYNC_TASK_IN_PROGRESS_WHEN_CLOSING_TCP_OR_DTLS_CONN)

    return status

# ==========================================================================================
# UDP OPERATION LOOPs
# ==========================================================================================


def udp_client_greetings_loop(op_wrker, connection_copy, sock):
    '''
    Function to perform the core activities of a the udp operations client loop
    '''
    if connection_copy is not None:
        # 2 - get conversation rules applicable
        # 7 - send sync messages (if any)
        done, conn_broken = op_wrker.send_greetings_message(
            connection_copy, sock)
        if done and not conn_broken:
            # 12 - prepare async messages in the 'ToDo List' (if any)
            detected_async_rules = op_wrker.detect_async_rules_for_beginning(connection_copy.id)
            connection_copy = register_async_rules(
                op_wrker, detected_async_rules, connection_copy)
            # 13 - update the 'Connection Register'
            op_wrker.update_act_register(
                ip=connection_copy.ip,
                port=connection_copy.port,
                connection_id=connection_copy.id,
                greetings_rule=True,
                detected_async_rules=detected_async_rules)


def udp_core_loop(op_wrker, source_ip, source_port, message_received,
                  connection_copy, sock=None):
    '''
    Function to perform the core activities of a the udp operations server loop
    '''
    if connection_copy is not None:
        # 2 - get conversation rules applicable
        regex_conv_rules, default_rule, empty_rule, captured_data =\
            op_wrker.detect_conversation_rules(connection_copy,
                                               message_received)

        # 3,4,5,6 - check and update memory variables, execute built-in memory operaitons and custom functions; 
        # and do the session ID change
        connection_copy = check_and_update_memory_and_session_and_do_memory_operations(
            op_wrker,
            connection_copy,
            external_input=message_received,
            detection_time=True,
            regex_conv_rules=regex_conv_rules,
            captured_data=captured_data)

        # 7 - send sync messages (if any)
        if not op_wrker.ext_conn_controller.client_mode:
            done_greeting_rule, _ = op_wrker.send_greetings_message(
                connection_copy, None)
            if done_greeting_rule:
                # 2 - get conversation rules applicable
                detected_async_rules = op_wrker.detect_async_rules_for_beginning(connection_copy.id)
                # 12 - prepare async messages in the 'ToDo List' (if any)
                connection_copy = register_async_rules(
                    op_wrker, detected_async_rules, connection_copy, message_received)
        else:
            done_greeting_rule = False

        executed_regex_conv_rules, detected_async_rules, conn_broken = execute_sync_rules(
            op_wrker, default_rule,
            empty_rule, regex_conv_rules,
            connection_copy, sock)

        if not conn_broken:
            # 8,9,10, 11 - check and update memory variables, execute built-in memory operaitons and custom functions; 
            # and do the session ID change
            connection_copy = check_and_update_memory_and_session_and_do_memory_operations(
                op_wrker,
                connection_copy,
                external_input=message_received,
                regex_conv_rules=regex_conv_rules,
                captured_data=captured_data)

            # 12 - prepare async messages in the 'ToDo List' (if any)
            connection_copy = register_async_rules(
                op_wrker, detected_async_rules, connection_copy, message_received)

            # 13 - update the 'Connection Register'
            end_connection = op_wrker.update_conn_register(
                connection_copy, regex_conv_rules, sock)

            # 14 - update the 'Activity Register'
            op_wrker.update_act_register(
                ip=source_ip,
                port=source_port,
                connection_id=connection_copy.id,
                greetings_rule=done_greeting_rule,
                executed_regex_conv_rules=executed_regex_conv_rules,
                default_rule=default_rule,
                empty_rule=empty_rule,
                detected_async_rules=detected_async_rules,
                captured_data=captured_data,
                end_connection=end_connection,
                ext_input=message_received)
            
    else:  # </if connection_copy>
        logger.warning("Connection copy obtained is None/null")


def udp_client(conn_ready_flag, op_wrker, addr, sock, mask):
    '''
    Function to process the operation loop of the udp server
    '''
    # 0 - get the data received
    if conn_ready_flag and (mask & selectors.EVENT_READ):
        message_received, source_ip, source_port = op_wrker.ext_conn_controller.udp_listen_socket(
            sock)

        message_received = op_wrker.apply_encoding_to_input(message_received)
        connection_copy = op_wrker.identify_connection(
            ip=source_ip,
            port=source_port,
            recv_data=message_received,
            conn_socket=sock,
            client_socket_id=addr[CLIENT_SOCKET_ID])
        message_received = op_wrker.check_and_execute_custom_function_pre_post_processor(
            message_received, connection_copy, True)
        udp_core_loop(op_wrker, source_ip, source_port,
                      message_received, connection_copy, sock)

    elif conn_ready_flag and (mask & selectors.EVENT_WRITE):
        connection_copy = op_wrker.identify_connection(
            ip=addr[ADDR_IP],
            port=addr[ADDR_PORT],
            recv_data=None,
            conn_socket=sock,
            client_socket_id=addr[CLIENT_SOCKET_ID])
        udp_client_greetings_loop(op_wrker, connection_copy, sock)

    req_proc_list.remove_request_from_processing_list_for_existing_conn(addr)


def udp_server(op_wrker, message_received, source_ip, source_port):
    '''
    Function to process the operation loop of the udp server
    '''

    message_received = op_wrker.apply_encoding_to_input(message_received)
    # 1 - identify connection and/or session according to regex expressions
    connection_copy = op_wrker.identify_connection(
        ip=source_ip,
        port=source_port,
        recv_data=message_received)
    message_received = op_wrker.check_and_execute_custom_function_pre_post_processor(
        message_received, connection_copy, True)

    udp_core_loop(op_wrker, source_ip, source_port,
                  message_received, connection_copy)

# ==========================================================================================
# TCP OPERATION LOOPS
# ==========================================================================================


def tcp_close_unaccepted_connection(op_wrker, socket_conn):
    '''
    Function to close unaccepted connections (max number of connections reached)
    '''
    logger.warn("Detected an unaccepted/registered connection, so closing it")
    op_wrker.ext_conn_controller.close_socket(socket_conn)


def tcp_get_external_input_from_socket(op_wrker, socket_conn, addr):
    '''
    Function to get input from a tcp socket
    '''
    error = False
    ext_input = None
    reconnection = True
    # 0 - get the data received
    try:
        # for the cliend mode scenario, check if there is any reconnection in progress before reading new input
        # just in case you read data from a socket that is going to be closed soon. The problem is that at this point,
        # we have not identified the connection, this happens after receiving the input
        while reconnection:
            reconnection = op_wrker.connection_register.check_if_any_reconnection_in_progress()
        ext_input = op_wrker.ext_conn_controller.receive_data(socket_conn)
    except:
        error = True
        logger.exception(
            f"Error receiving data in the socket:{addr}, it should be closed")
        op_wrker.ext_conn_controller.close_socket(socket_conn)

    if (ext_input is None or len(ext_input) == 0) and not error:
        logger.debug(f"No data received from the TCP connection from {addr}")

    return ext_input, error


def tcp_or_dtls_greetings_loop(tcp_dtls_conn_ready_flag, op_wrker, addr, socket_conn,
                               recv_data=None, tcp_or_dtls_core_loop_in_progress=False,
                               connection_copy=None):
    '''
    Function to do the first loop when the greetings message is sent
    '''
    if interlanguage_bool_check(op_wrker.cnv_rules.Conversation.Greetings.Enable):
        close_after_answering_mode = (
            (op_wrker.ext_conn_controller.udp_protocol and op_wrker.ext_conn_controller.encrypted) or
            not op_wrker.ext_conn_controller.udp_protocol) and op_wrker.connection_register.close_tcp
        enable_rule_triggered_close_socket = op_wrker.connection_register.enable_rule_triggered_close_socket
        client_and_close_after_answer_mode = close_after_answering_mode and\
            op_wrker.connection_register.client_mode

        if connection_copy is None:
            # 1 - identify connection and/or session according to regex expressions
            # (most likely a new connection) ip, port, conn = None, recv_data = None,
            # client_socket_id = None)
            if op_wrker.connection_register.client_mode:
                connection_copy = op_wrker.identify_connection(
                    ip=addr[ADDR_IP],
                    port=addr[ADDR_PORT],
                    recv_data=recv_data,
                    conn_socket=socket_conn,
                    client_socket_id=addr[CLIENT_SOCKET_ID])
            else:
                connection_copy = op_wrker.identify_connection(
                    ip=addr[ADDR_IP],
                    port=addr[ADDR_PORT],
                    recv_data=recv_data,
                    conn_socket=socket_conn)
        if connection_copy is not None:
            # 2 - get conversation rules applicable
            # 7 - send sync messages (if any)
            done, conn_broken = op_wrker.send_greetings_message(
                connection_copy, socket_conn)
            async_rules_check_for_socket_close = False

            if done and not conn_broken:
                # 12 - prepare async messages in the 'ToDo List' (if any)
                detected_async_rules = op_wrker.detect_async_rules_for_beginning(connection_copy.id)
                async_rules_check_for_socket_close = (
                    detected_async_rules is None or not len(detected_async_rules) > 0)

                connection_copy = register_async_rules(
                    op_wrker, detected_async_rules, connection_copy)

                # 13 - update the 'Connection Register'
                op_wrker.update_act_register(
                    tcp_dtls_conn_ready_flag=tcp_dtls_conn_ready_flag,
                    ip=addr[ADDR_IP],
                    port=addr[ADDR_PORT],
                    connection_id=connection_copy.id,
                    greetings_rule=True,
                    detected_async_rules=detected_async_rules)

                # 15 - check if the current socket should be closed if not async rules are detected
            if (close_after_answering_mode or enable_rule_triggered_close_socket):
                if (close_after_answering_mode and
                    not tcp_or_dtls_core_loop_in_progress and
                    async_rules_check_for_socket_close and
                        not client_and_close_after_answer_mode):
                    op_wrker.check_and_close_tcp_or_dtls_socket_but_not_connection(
                        connection_copy)
                req_proc_list.\
                    remove_request_from_processing_list_for_managing_conn_closing_after_answering(
                        addr)
        else:
            logger.info(
                f"Connection not recognized in the greetings loop from {addr}")


def tcp_or_dtls_core_loop(op_wrker, addr, socket_conn, ext_input, tcp_dtls_conn_ready_flag, mask):
    '''
    Function to perform the core activities of a the tcp or dtls operaiton loops
    '''
    if socket_conn is not None and socket_conn.fileno() != CLOSED_SOCKET:
        # Loop initiliazation
        close_after_answering_mode = (
            (op_wrker.ext_conn_controller.udp_protocol and op_wrker.ext_conn_controller.encrypted) or
            not op_wrker.ext_conn_controller.udp_protocol) and op_wrker.connection_register.close_tcp
        client_mode = op_wrker.connection_register.client_mode
        client_and_close_after_answer_mode = close_after_answering_mode and\
            client_mode
        enable_rule_triggered_close_socket = op_wrker.connection_register.enable_rule_triggered_close_socket
        success_reconnection = False
        something_to_send = False
        rule_triggered_close_socket = False
        reconnect_before_rule_execution = False
        ext_input = op_wrker.apply_encoding_to_input(ext_input)

        # 1 - identify connection and/or session according to regex expressions
        if client_mode:
            connection_copy = op_wrker.identify_connection(
                ip=addr[ADDR_IP],
                port=addr[ADDR_PORT],
                conn_socket=socket_conn,
                recv_data=ext_input,
                client_socket_id=addr[CLIENT_SOCKET_ID])
        else:
            connection_copy = op_wrker.identify_connection(
                ip=addr[ADDR_IP],
                port=addr[ADDR_PORT],
                conn_socket=socket_conn,
                recv_data=ext_input)

        if connection_copy is not None:
            ext_input = op_wrker.check_and_execute_custom_function_pre_post_processor(
                ext_input, connection_copy, True)
            # Wait for a socket reconnection if needed
            status = wait_for_tcp_or_dtls_reconnection(
                op_wrker, connection_copy)

            if status == ConnectionStatus.OPEN:
                # 2 - get conversation rules applicable
                regex_conv_rules, default_rule, empty_rule, captured_data = op_wrker.detect_conversation_rules(
                    connection_copy,
                    ext_input)

                if enable_rule_triggered_close_socket and not close_after_answering_mode and client_mode:
                    reconnect_before_rule_execution = op_wrker.check_exec_rules_for_reconnection(
                        regex_conv_rules)

                if client_and_close_after_answer_mode or (reconnect_before_rule_execution and client_mode):
                    rule_check = check_sync_rules_for_something_to_send(
                        regex_conv_rules)
                    something_to_send = rule_check or (
                        default_rule is not None and interlanguage_bool_check(default_rule.Enable)) or (
                        empty_rule is not None and interlanguage_bool_check(empty_rule.Enable))

                # 3,4,5,6 - check and update memory variables, execute built-in memory operaitons and custom functions; 
                # and do the session ID change
                connection_copy = check_and_update_memory_and_session_and_do_memory_operations(
                    op_wrker,
                    connection_copy,
                    external_input=ext_input,
                    detection_time=True,
                    regex_conv_rules=regex_conv_rules,
                    captured_data=captured_data)

                # For client mode, at this moment the socket connection should be closed (server already answered and
                # potentially has closed the connection). So, if the rule requires reconnection or we are in a context
                # of close after answer, we have to reconnect
                if (client_and_close_after_answer_mode or reconnect_before_rule_execution) and something_to_send:
                    success_reconnection, connection_copy, socket_conn = do_tcp_or_dtls_socket_reconnection(
                        op_wrker, connection_copy)

                if (mask & selectors.EVENT_WRITE) or (
                    (client_and_close_after_answer_mode or reconnect_before_rule_execution) and
                        success_reconnection):
                    # 7 - send sync messages (if any)
                    # send greetings message if applicable
                    tcp_or_dtls_greetings_loop(
                        tcp_dtls_conn_ready_flag, op_wrker, addr, socket_conn,
                        tcp_or_dtls_core_loop_in_progress=True,
                        connection_copy=connection_copy)

                    executed_regex_conv_rules, detected_async_rules, conn_broken = execute_sync_rules(
                        op_wrker, default_rule,
                        empty_rule, regex_conv_rules,
                        connection_copy, socket_conn)

                    if not conn_broken:
                        # 8,9,10,11 - check and update memory variables, execute built-in memory operaitons and custom functions; 
                        # and do the session ID change
                        connection_copy = check_and_update_memory_and_session_and_do_memory_operations(
                            op_wrker,
                            connection_copy,
                            external_input=ext_input,
                            regex_conv_rules=regex_conv_rules,
                            captured_data=captured_data)

                        # 12 - prepare async messages in the 'ToDo List' (if any)
                        connection_copy = register_async_rules(
                            op_wrker, detected_async_rules, connection_copy, ext_input)

                        # 13 - update the 'Connection Register'
                        end_connection = op_wrker.update_conn_register(
                            connection_copy, regex_conv_rules, socket_conn)

                        # 14 - update the 'Activity Register'
                        op_wrker.update_act_register(
                            tcp_dtls_conn_ready_flag=tcp_dtls_conn_ready_flag,
                            ip=addr[ADDR_IP],
                            port=addr[ADDR_PORT],
                            connection_id=connection_copy.id,
                            executed_regex_conv_rules=executed_regex_conv_rules,
                            default_rule=default_rule,
                            empty_rule=empty_rule,
                            detected_async_rules=detected_async_rules,
                            captured_data=captured_data,
                            end_connection=end_connection,
                            ext_input=ext_input)

                    # 15 - Check if any executed rule should close the conection (in the case it is not enable);
                    # and if the flag 'sync_done_async_in_progress flag' should be enable, or if the current socket
                    # should be closed or not if not async rules are detected
                    if enable_rule_triggered_close_socket:
                        rule_triggered_close_socket = op_wrker.check_exec_rules_for_closing(
                            executed_regex_conv_rules)

                    # If there are async rules to execute
                    if (close_after_answering_mode or rule_triggered_close_socket) and (
                            detected_async_rules is not None and (len(detected_async_rules) > 0)):
                        op_wrker.check_and_enable_sync_done_async_in_progress_flag(
                            connection_copy)

                    # If not async rules to execute
                    elif (close_after_answering_mode or enable_rule_triggered_close_socket) and (
                            detected_async_rules is None or not len(detected_async_rules) > 0):

                        # Server mode
                        if not client_mode and (not enable_rule_triggered_close_socket or rule_triggered_close_socket):
                            op_wrker.check_and_close_tcp_or_dtls_socket_but_not_connection(
                                connection_copy)

                        # If we have to close the socket for a rule, and we are in client mode; we should reconnect (if not done previously)
                        elif enable_rule_triggered_close_socket and rule_triggered_close_socket and\
                                client_mode and not reconnect_before_rule_execution:
                            # close the socket
                            op_wrker.check_and_close_tcp_or_dtls_socket_but_not_connection(
                                connection_copy)
                            # reconnect
                            success_reconnection, connection_copy, socket_conn = do_tcp_or_dtls_socket_reconnection(
                                op_wrker, connection_copy)

                        req_proc_list.\
                            remove_request_from_processing_list_for_managing_conn_closing_after_answering(
                                addr)

                else:  # </if (mask & selectors.EVENT_WRITE) or (client_and_close_after_answer_mode and success_reconnection)>
                    logger.warning(
                        f"Socket not able to send answers for the connection:{connection_copy.id}")
            else:  # </if connection open>
                logger.warning(
                    f"Connection:{connection_copy.id} not 'OPEN' at tin the TCP core loop")
        else:  # </if connection_copy>
            logger.warning(
                f"Connection is None for the socket:{addr}. it means that likely the max number of connections is reached")
            tcp_close_unaccepted_connection(op_wrker, socket_conn)
    else:  # </if socket closed>
        logger.warning(
            f"TCP or DTLS core loop not executed, socket is closed. Socket data:{addr}")


def tcp_or_dtls_client(op_wrker, socket_conn, addr, mask, tcp_dtls_conn_ready_flag):
    '''
    Function to process the operation loop of the tcp client
    '''
    error = False

    # 0 - get the data received
    if tcp_dtls_conn_ready_flag and (mask & selectors.EVENT_READ):
        ext_input, error = tcp_get_external_input_from_socket(
            op_wrker, socket_conn, addr)
        if not error:
            tcp_or_dtls_core_loop(op_wrker, addr, socket_conn,
                                  ext_input, tcp_dtls_conn_ready_flag, mask)

    elif tcp_dtls_conn_ready_flag and (mask & selectors.EVENT_WRITE):
        tcp_or_dtls_greetings_loop(
            tcp_dtls_conn_ready_flag, op_wrker, addr, socket_conn)

    req_proc_list.remove_request_from_processing_list_for_existing_conn(addr)


def tcp_or_dtls_server(op_wrker, mask, new_conn_flag, tcp_dtls_conn_ready_flag, socket_conn, addr):
    '''
    Function to process the operation loop of the tcp server. The flag 'new_conn_flag' means 
    the tcp is ready for the three way handshake.
    '''
    if new_conn_flag:
        # Request complete: existing connection
        req_proc_list.remove_request_from_processing_list_for_new_conn(addr)

    elif tcp_dtls_conn_ready_flag and (mask & selectors.EVENT_READ):
        ext_input, error = tcp_get_external_input_from_socket(
            op_wrker, socket_conn, addr)
        if not error:
            tcp_or_dtls_core_loop(op_wrker, addr, socket_conn,
                                  ext_input, tcp_dtls_conn_ready_flag, mask)

        # Request complete: existing connection
        req_proc_list.remove_request_from_processing_list_for_existing_conn(
            addr)

    elif tcp_dtls_conn_ready_flag and (mask & selectors.EVENT_WRITE):
        # send greetings message
        tcp_or_dtls_greetings_loop(
            tcp_dtls_conn_ready_flag, op_wrker, addr, socket_conn)
        # Request complete: new connection
        req_proc_list.remove_request_from_processing_list_for_existing_conn(
            addr)
    else:
        # Request complete: existing connection
        req_proc_list.remove_request_from_processing_list_for_existing_conn(
            addr)

# ==========================================================================================
# ASYNCHRONOUS TASKS FUNCTIONS
# ==========================================================================================


def async_loop(op_wrker, conns_timed_out, todos_to_do):
    '''
    Function to do the async tasks obtained as result of the oversee loop of the main thread
    This is the async (worker) loop 
    '''
    logger.debug(
        "Launched an operation worker for the async tasks")

    op_wrker.send_timeouts_messages(conns_timed_out)
    # update the 'Activity Register' about the connections timed out
    if len(conns_timed_out) > 0:
        op_wrker.update_act_register(
            list_connections_timed_out=conns_timed_out)
    # 'executed_async_rule' = {connection_id: [List of executed async rules], ... }
    # 'connections_used_copies' = {connection_id: conection_copy_object, ... }
    executed_async_rules, connections_used_copies = op_wrker.execute_async_rules(
        todos_to_do, WAITING_TIME_ASYNC_TASK_IN_PROGRESS_WHEN_CLOSING_TCP_OR_DTLS_CONN)
    enable_rule_triggered_close_socket = op_wrker.connection_register.enable_rule_triggered_close_socket

    # For each connection affected by the async rules
    for connection_id, list_of_executed_async_rules in executed_async_rules.items():
        # detect potential new async rules to be executed after
        # the execution of the current async rules
        new_async_rules = op_wrker.detect_async_rules(
            list_of_executed_async_rules, connection_id)

        # current connection
        connection_copy = connections_used_copies[connection_id]
        # register them in the ToDo List
        connection_copy = register_async_rules(
            op_wrker, new_async_rules, connection_copy)

        # Update the connection register
        end_connection = op_wrker.update_conn_register(
            connection_copy=connection_copy,
            executed_conv_rules=list_of_executed_async_rules,
            socket_conn=connection_copy.get_connection_socket())

        # update the 'Activity Register' about the async conversation rules executed
        op_wrker.update_act_register(
            ip=connection_copy.ip,
            port=connection_copy.port,
            connection_id=connection_id,
            detected_async_rules=new_async_rules,
            end_connection=end_connection,
            async_activity_flag=True,
            executed_async_rules=list_of_executed_async_rules)

        # check if the current socket should be closed or not, if not async rules are detected
        if enable_rule_triggered_close_socket:
            rule_triggered_close_socket = op_wrker.check_exec_rules_for_closing(
                list_of_executed_async_rules)
        else:
            rule_triggered_close_socket = False

        async_rules_check_for_closing = new_async_rules is None or not len(
            new_async_rules) > 0

        close_after_answering_mode = (
            (op_wrker.ext_conn_controller.udp_protocol and op_wrker.ext_conn_controller.encrypted) or
            not op_wrker.ext_conn_controller.udp_protocol) and op_wrker.connection_register.close_tcp

        if (close_after_answering_mode or enable_rule_triggered_close_socket) and async_rules_check_for_closing:
            end_async_rules_processing_for_closing_tcp_or_dtls_conn_after_answer(
                connection_copy, op_wrker, rule_triggered_close_socket)
