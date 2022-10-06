"""
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega external connector
=================================================
Module: interaction_worker.py
Author: Alberto Dominguez

This module contains the business logic of interaction thread,
which receives any incomming connection/message
"""
import logging
import threading
import time

import operation_variables.request_processing_list as req_proc_list
from ext_conn_comms.ext_comm_controller import CLOSED_SOCKET
from utils.interoperability_py_go import interlanguage_bool_check
from utils.memory_operations import compare_two_memory_variables_values

from ext_conn_threads import operation_loops as op_loops
from ext_conn_threads import operation_worker as op_wrkr

# logger
logger = logging.getLogger(__name__)


class InteractionWorker:
    '''
    Object to provide the tools that interaction worker needs
    to manage receiving information from the external thrid party
    '''

    def __init__(self, ext_conn_controller, conversation_rules, connection_register,
                 activity_register, todo_list, exec_dashboard, hash_conversation_rules_used,
                 cleaning_register, custom_functions_name,number_rule_checker_subworkers):
        self.ext_conn_controller = ext_conn_controller
        self.cnv_rules = conversation_rules
        self.connection_register = connection_register
        self.activity_register = activity_register
        self.todo_list = todo_list
        self.exec_dashboard = exec_dashboard
        self.hash_conversation_rules_used=hash_conversation_rules_used
        self.cleaning_register=cleaning_register
        self.custom_functions_name=custom_functions_name
        self.number_rule_checker_subworkers=number_rule_checker_subworkers

    # ==========================================================================================
    # AUX FUNCTIONS
    # ==========================================================================================
    def server_events_handler(self, key):
        '''
        Function to manage the events received in the tcp or udp+dtls server. It accepts the connection for new ones,
        or detects when it can be used
        '''
        # Status flags
        new_conn_flag = False
        tcp_dtls_conn_ready_flag = False

        if key.data is None:
            # key.fileobj = listening socket in this case
            conn, addr = self.ext_conn_controller.accept_new_connection(
                key.fileobj)
            if (not req_proc_list.check_request_in_processing_list_for_new_conn(addr)
                ) and (
               not req_proc_list.check_request_in_processing_list_for_managing_conn_closing_after_answering(
                   addr)
               ) and (
                   conn is not None and addr is not None
            ):
                req_proc_list.add_request_in_processing_list_for_new_conn(addr)
                new_conn_flag = True
        else:
            addr = key.data
            conn = False
            if (not req_proc_list.check_request_in_processing_list_for_new_or_exiting_conn(addr)
                ) and (
               not req_proc_list.check_request_in_processing_list_for_managing_conn_closing_after_answering(
                   addr)):
                req_proc_list.add_request_in_processing_list_for_existing_conn(
                    addr)
                tcp_dtls_conn_ready_flag = True
                conn = key.fileobj

        return new_conn_flag, tcp_dtls_conn_ready_flag, conn, addr

    def client_events_handler(self, key):
        '''
        Function to manage the events received in the tcp server. It accepts the connection for new ones,
        or detects when it can be used
        '''
        # Status flags
        conn_ready_flag = False

        if key.data is not None:
            addr = key.data
            sock = False
            if not req_proc_list.check_request_in_processing_list_for_exiting_conn(addr):
                sock = key.fileobj
                if sock.fileno() != CLOSED_SOCKET:
                    req_proc_list.add_request_in_processing_list_for_existing_conn(
                        addr)
                    conn_ready_flag = True
                else:
                    logger.info(
                        f"Client socket from:{addr} closed, not actions will be done")

        return conn_ready_flag, sock, addr

    # ==========================================================================================
    # STOP FUNCTIONS
    # ==========================================================================================
    def stop_running(self):
        '''
        Method to stop the execution of the execution of the interaction worker thread
        '''
        logger.warning("Stoping the execution of the Interaction worker thread (the one that listens "
                       + "the external socket)")

        # Ending external/listening socket/clietn sockets
        self.ext_conn_controller.close_socket()

    # ==========================================================================================
    # OPERATION FUNCTIONS - UDP without DTLS
    # ==========================================================================================

    def run_as_udp_client(self):
        '''
        Method to start the execution as an UDP client
        '''
        logger.info("Starting the operation as an UDP client")

        while(self.exec_dashboard.check_execution_flag()):
            events = self.ext_conn_controller.wait_for_events()
            # Check events (if any)
            if events is not None and len(events) > 0:
                for key, mask in events:
                    conn_ready_flag, sock, addr = self.client_events_handler(
                        key)
                    if conn_ready_flag:
                        # Creating an operation worker and launch it in a new thread
                        op_wrker = op_wrkr.OperationWorker(
                            conversation_rules=self.cnv_rules,
                            connection_register=self.connection_register,
                            activity_register=self.activity_register,
                            todo_list=self.todo_list,
                            exec_dashboard=self.exec_dashboard,
                            ext_conn_controller=self.ext_conn_controller,
                            hash_conversation_rules_used=self.hash_conversation_rules_used,
                            cleaning_register=self.cleaning_register,
                            custom_functions_name=self.custom_functions_name,
                            number_rule_checker_subworkers=self.number_rule_checker_subworkers)

                        new_thread = threading.Thread(
                            target=op_loops.udp_client,
                            name=op_wrker.thread_name,
                            args=(conn_ready_flag, op_wrker, addr, sock, mask))
                        new_thread.start()

    def run_as_udp_server(self):
        '''
        Method to start the execution as UDP server
        '''
        logger.info("Starting the operation as a UDP server")
        while(self.exec_dashboard.check_execution_flag()):
            message_received, source_ip, source_port = self.ext_conn_controller.udp_listen_socket()
            if message_received is not None:
                # Creating the interaction worker and launch it in a new thread
                op_wrker = op_wrkr.OperationWorker(
                    conversation_rules=self.cnv_rules,
                    connection_register=self.connection_register,
                    activity_register=self.activity_register,
                    todo_list=self.todo_list,
                    exec_dashboard=self.exec_dashboard,
                    ext_conn_controller=self.ext_conn_controller,
                    hash_conversation_rules_used=self.hash_conversation_rules_used,
                    cleaning_register=self.cleaning_register,
                            custom_functions_name=self.custom_functions_name,
                            number_rule_checker_subworkers=self.number_rule_checker_subworkers)

                new_thread = threading.Thread(
                    target=op_loops.udp_server,
                    name=op_wrker.thread_name,
                    args=(op_wrker, message_received, source_ip,
                          source_port,))
                new_thread.start()
            # send pending udp messages ready to send
            self.ext_conn_controller.udp_send_messages_from_sending_queue()

    # ==========================================================================================
    # OPERATION FUNCTIONS - TCP or DTLS
    # ==========================================================================================

    def run_as_tcp_or_dtls_client(self):
        '''
        Method to start the execution as a TCP or DTLS client
        '''
        logger.info("Starting the operation as an TCP or DTLS client")
        # Initialise client sockets
        self.ext_conn_controller.tcp_connect_all_sockets()
        logger.info(
            "TCP ot DTLS connections established successfully with the target")
        while(self.exec_dashboard.check_execution_flag()):
            events = self.ext_conn_controller.wait_for_events()
            # Check events (if any)
            if events is not None and len(events) > 0:
                for key, mask in events:
                    tcp_dtls_conn_ready_flag, socket_conn, addr = self.client_events_handler(
                        key)
                    if tcp_dtls_conn_ready_flag:
                        # Creating the interaction worker and launch it in a new thread
                        op_wrker = op_wrkr.OperationWorker(
                            conversation_rules=self.cnv_rules,
                            connection_register=self.connection_register,
                            activity_register=self.activity_register,
                            todo_list=self.todo_list,
                            exec_dashboard=self.exec_dashboard,
                            ext_conn_controller=self.ext_conn_controller,
                            hash_conversation_rules_used=self.hash_conversation_rules_used,
                            cleaning_register=self.cleaning_register,
                            custom_functions_name=self.custom_functions_name,
                            number_rule_checker_subworkers=self.number_rule_checker_subworkers)

                        new_thread = threading.Thread(
                            target=op_loops.tcp_or_dtls_client,
                            name=op_wrker.thread_name,
                            args=(op_wrker, socket_conn, addr, mask,
                                  tcp_dtls_conn_ready_flag))
                        new_thread.start()

    def run_as_tcp_or_dtls_server(self):
        '''
        Method to start the execution as TCP or DTLS server
        '''
        logger.info("Starting the operation as a TCP or DTLS server")
        self.ext_conn_controller.enable_listen_socket()

        while(self.exec_dashboard.check_execution_flag()):
            events = self.ext_conn_controller.wait_for_events()
            # Check events (if any)
            if events is not None and len(events) > 0:
                for key, mask in events:
                    new_conn_flag, tcp_dtls_conn_ready_flag, socket_conn, addr = self.server_events_handler(
                        key)
                    # is there something to do?
                    if new_conn_flag or tcp_dtls_conn_ready_flag:
                        # Creating the operation worker and launching it in a new thread
                        op_wrker = op_wrkr.OperationWorker(
                            conversation_rules=self.cnv_rules,
                            connection_register=self.connection_register,
                            activity_register=self.activity_register,
                            todo_list=self.todo_list,
                            exec_dashboard=self.exec_dashboard,
                            ext_conn_controller=self.ext_conn_controller,
                            hash_conversation_rules_used=self.hash_conversation_rules_used,
                            cleaning_register=self.cleaning_register,
                            custom_functions_name=self.custom_functions_name,
                            number_rule_checker_subworkers=self.number_rule_checker_subworkers)

                        new_thread = threading.Thread(
                            target=op_loops.tcp_or_dtls_server,
                            name=op_wrker.thread_name,
                            kwargs={'op_wrker': op_wrker,
                                    'mask': mask,
                                    'new_conn_flag': new_conn_flag,
                                    'tcp_dtls_conn_ready_flag': tcp_dtls_conn_ready_flag,
                                    'socket_conn': socket_conn,
                                    'addr': addr, })
                        new_thread.start()

# ==========================================================================================
# STARTING FUNCTION
# ==========================================================================================


def check_execution_conditions(multi_ext_conn_mem, conditional_execution_info):
    '''
    Function to check if a set of memory conditions has the right values for 
    starting the execution of the external connector
    '''
    ip = None
    port = None
    all_conditions_ok = True

    # check execution conditions
    for condition in conditional_execution_info.Conditions:

        # is the memory variable present for conditional execution?
        conditional_variable_found = False
        # does it have the right value?
        conditional_variable_value_ok = False

        # is the memory variable in the Redis?
        for mem_element_name in multi_ext_conn_mem:
            if condition.VarName == mem_element_name:
                conditional_variable_found |= True

                # Does it have the right value?
                if (condition.Value == multi_ext_conn_mem[mem_element_name] or
                    (condition.ReferenceVariable in multi_ext_conn_mem and
                     compare_two_memory_variables_values(
                         multi_ext_conn_mem[mem_element_name], 
                         multi_ext_conn_mem[condition.ReferenceVariable])
                     )):
                    conditional_variable_value_ok |= True
                    break
                else:
                    conditional_variable_value_ok |= False
            else:
                conditional_variable_found |= False

        # if a memory variable that works as condition is not present, or it is but the value does not match
        # stop the check and do not start the exectuion of the external connector
        if not conditional_variable_found:
            all_conditions_ok &= False
            logger.info(f"The memory variable '{condition.VarName}' not found in the multi external " +
                        "connector memory variables, so the execution should not start")
            break
        elif not conditional_variable_value_ok:
            all_conditions_ok &= False
            logger.info(f"The memory variable '{condition.VarName}' does not have the rigth value in the multi external " +
                        "connector memory variables, so the execution should not start")
            break
        else:
            all_conditions_ok &= True

    # not waiting means we can start (conditions are ok)
    if all_conditions_ok:
        for mem_element_name in multi_ext_conn_mem:
            # get ip (if applicable)
            if (len(conditional_execution_info.MemVarIp) > 0 and
                    conditional_execution_info.MemVarIp.upper() == mem_element_name.upper()):
                ip = multi_ext_conn_mem[mem_element_name]

            # get port (if applicable)
            if (len(conditional_execution_info.MemVarPort) > 0 and
                    conditional_execution_info.MemVarPort.upper() == mem_element_name.upper()):
                port = multi_ext_conn_mem[mem_element_name]

    return all_conditions_ok, ip, port


def start_interaction_worker(in_wrkr):
    '''
    This function is aimed to get an interaction worker object and run it in a new thread.
    '''
    # Check if the conditional execution is enabled
    if (interlanguage_bool_check(in_wrkr.cnv_rules.ExtOperation.ConditionalExecution.Enable) and
            in_wrkr.connection_register.redis_connected):
        logger.info(
            "Conditional execution enabled, waiting for execution conditions to be satisfied...")
        all_conditions_ok = False

        while(in_wrkr.exec_dashboard.check_execution_flag() and not all_conditions_ok):
            multi_ext_conn_mem = in_wrkr.connection_register.get_copy_multi_ext_connectors_memory()
            all_conditions_ok, ip, port = check_execution_conditions(multi_ext_conn_mem,
                                                                     in_wrkr.cnv_rules.ExtOperation.ConditionalExecution)
            if not all_conditions_ok:
                time.sleep(1)  # wait a second before checking again
            else:
                in_wrkr.ext_conn_controller.modify_ip_and_port(
                    ip, port, in_wrkr.cnv_rules.ExtOperation.MaxConcurrentConnections)

    # Check if the execution is delayed
    if in_wrkr.cnv_rules.ExtOperation.Delay > 0:
        logger.info("Waiting before starting the execution...")
        time.sleep(in_wrkr.cnv_rules.ExtOperation.Delay)
        logger.info("Resuming the execution...")

    # External interaction is started
    in_wrkr.exec_dashboard.mark_interaction_as_started()
    
    # UDP CLIENT without DTLS
    if in_wrkr.ext_conn_controller.client_mode and in_wrkr.ext_conn_controller.udp_protocol\
            and not in_wrkr.ext_conn_controller.encrypted:
        in_wrkr.run_as_udp_client()
        in_wrkr.stop_running()

    # UDP SERVER without DTLS
    elif not in_wrkr.ext_conn_controller.client_mode and in_wrkr.ext_conn_controller.udp_protocol\
            and not in_wrkr.ext_conn_controller.encrypted:
        in_wrkr.run_as_udp_server()
        in_wrkr.stop_running()

    # UDP CLIENT with DTLS
    if in_wrkr.ext_conn_controller.client_mode and in_wrkr.ext_conn_controller.udp_protocol\
            and in_wrkr.ext_conn_controller.encrypted:
        in_wrkr.run_as_tcp_or_dtls_client()
        in_wrkr.stop_running()

    # UDP SERVER with DTLS
    elif not in_wrkr.ext_conn_controller.client_mode and in_wrkr.ext_conn_controller.udp_protocol\
            and in_wrkr.ext_conn_controller.encrypted:
        in_wrkr.run_as_tcp_or_dtls_server()
        in_wrkr.stop_running()

    # TCP CLIENT
    elif in_wrkr.ext_conn_controller.client_mode and not in_wrkr.ext_conn_controller.udp_protocol:
        in_wrkr.run_as_tcp_or_dtls_client()
        in_wrkr.stop_running()

    # TCP SERVER
    else:
        in_wrkr.run_as_tcp_or_dtls_server()
        in_wrkr.stop_running()
