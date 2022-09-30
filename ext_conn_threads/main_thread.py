"""
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega external connector
=================================================
Module: main_thread.py
Author: Alberto Dominguez

This module contains the operation of the main thread, which is a
loop-like execution (oversee loop).
oversee loop:
    1 - launch the async worker to check timers and do async tasks
    2 - check 'Activity Register' (information to send to the engine)
    3 - send information to engine / check for orders
    4 - execute orders
    5 - wait for additional orders from engine or waiting timeout
"""
import logging
import threading
import time

from ext_conn_comms import engine_comm_service as eng_com
from logic_modules import order_module as ord_mod
from operation_variables import activity_register as act_reg
from operation_variables import connection_register as con_reg
from operation_variables import exec_dashboard as exdb
from operation_variables import todo_list as td_lst

from ext_conn_threads import async_worker as async_wrkr
from ext_conn_threads import interaction_worker as int_wrkr

# logger
logger = logging.getLogger(__name__)

# Constant
NUMBER_LOOPS_TO_CLEAN_CONN_REGISTER = 100
WAITING_FOR_THREADS_ENDING = 5  # seconds

# ==========================================================================================
# OVERSEE MAIN THREAD FUNCTIONS
# ==========================================================================================


def process_engine_response(processed_reply, context):
    '''
    Function to process any message from the engine, mainly the response
    of the engine after informing it about the activitites registered during
    the execution of the external connector
    '''
    if (processed_reply is not None and
        len(processed_reply) > 0 and
            processed_reply[eng_com.M_TYPE] == eng_com.MessageType.ORDER.value):

        ord_mod.process_new_order(processed_reply[eng_com.M_BODY], context)


def send_activities_to_engine(context):
    '''
    Function to send the activities registered during execution
    '''
    processed_reply = None

    # 2 - check 'Activity Register' (information to send to the engine)
    activities_to_send = context.activity_register.get_not_read_activities()

    # 3 - send information to engine / check for orders
    if len(activities_to_send) > 0:
        _, processed_reply, _ = eng_com.send_info_to_engine(
            msg_type=eng_com.MessageType.INFO,
            info=activities_to_send,
            ext_conn_context=context)

    return processed_reply


def oversee_loop(context):
    '''
    This function is the main one for operation for the main thread, controlling the execution
    of the external connector
    '''
    # launch the async worker
    new_thread = threading.Thread(
        target=async_wrkr.run_async_worker,
        name="AsyncWrkr",
        kwargs={
            'exec_dashboard': context.exec_dashboard,
            'connection_register': context.connection_register,
            'todo_list': context.todo_list,
            'cnv_rules': context.cnv_rules,
            'activity_register': context.activity_register,
            'ext_conn_controller': context.ext_conn_controller,
            'time_between_async_loops': context.time_between_async_loops,
            'number_async_loops_to_clean_conn_register':
            context.number_async_loops_to_clean_conn_register,
            'time_between_async_loops': context.time_between_async_loops,
            'initial_delay_client_mode_async_thread':
            context.initial_delay_client_mode_async_thread,
            'hash_conversation_rules_used': context.hash_conversation_rules_used,
            'cleaning_register': context.cleaning_register,
            'custom_functions_name': context.custom_functions_name})
    new_thread.start()

    # 1 - check the execution flag
    while (context.exec_dashboard.check_execution_flag()):
        # 2 - check 'Activity Register' (information to send to the engine) AND
        # 3 - send information to engine / check for orders
        processed_reply = send_activities_to_engine(context)

        # 4 - execute orders
        process_engine_response(processed_reply, context)

        # 5 - wait for additional orders from engine or waiting timeout
        msg_received, processed_reply = eng_com.wait_for_engine_message(
            context)

        if msg_received is not None:
            # 4 - execute orders
            process_engine_response(processed_reply, context)

# ==========================================================================================
# START & END MAIN THREAD FUNCTIONS
# ==========================================================================================


def start_operation(context):
    '''
    This function is the main one for operating the external connector, it starts the interaction thread
    '''
    logger.info("Starting the operation of the external connector...")

    # Creating the operation context variables
    connection_register = con_reg.ConnectionRegister(
        config_ext_conn_timeout=context.timeout_ext_conn,
        conv_rules_mem_variables=context.cnv_rules.MemoryVariables,
        session_cnfg=context.cnv_rules.ExtOperation.Session,
        max_concurrent_connections=context.max_concurrent_connections,
        use_port_as_identifier=context.cnv_rules.ExtOperation.UsePortForConnectionIdentification,
        op_mode=context.op_mode,
        encoding=context.cnv_rules.ExtOperation.Encoding,
        close_tcp_after_answering=context.cnv_rules.ExtOperation.CloseTCPConnectionAfterAnswering,
        interaction_timeout=context.cnv_rules.ExtOperation.InteractionTimeout,
        socket_transport_protocol=context.cnv_rules.ExtOperation.TransportProtocol,
        session_update_enable=context.cnv_rules.ExtOperation.Session.Update,
        session_update_when=context.cnv_rules.ExtOperation.Session.Update.When,
        memory_update_when=context.cnv_rules.ExtOperation.MemoryUpdateWhen,
        memory_operations_when=context.cnv_rules.ExtOperation.MemoryOpsWhen,
        encrypted=context.encrypted,
        custom_function_when=context.cnv_rules.ExtOperation.CustomFunctionsWhen,
        report_memory=context.cnv_rules.ExtOperation.ReportMemory,
        custom_function_preprocessor=context.cnv_rules.ExtOperation.CustomFunctionPreprocessor,
        custom_function_postprocessor=context.cnv_rules.ExtOperation.CustomFunctionPostprocessor,
        rule_triggered_close_socket=context.cnv_rules.ExtOperation.EnablesRulesCloseSocket,
        multi_ext_conn_mem_var_enable=context.cnv_rules.ExtOperation.MemVarMultiExtConnEnable,
        redis_ip=context.redis_ip,
        redis_port=context.redis_port,
        redis_password=context.redis_password,
        redis_tls=context.redis_tls,
        redis_ca_cert=context.redis_ca_cert,
        redis_use_client_cert=context.redis_use_client_cert,
        redis_client_cert=context.redis_client_cert,
        redis_priv_key_protected=context.redis_priv_key_protected,
        redis_priv_key_password=context.redis_priv_key_password,
        redis_priv_key_client=context.redis_priv_key_client,
        overwrite_multi_ext_conn_mem_vars_during_init=context.cnv_rules.ExtOperation.MultiExtConnMemOverwriteDuringInit)

    # Only go on with the execution if Redis server is not used, or it is used and the connection is working
    if not connection_register.multi_ext_conn_mem_var_enable or (
            connection_register.multi_ext_conn_mem_var_enable and connection_register.redis_connected):
        todo_list = td_lst.ToDoList(connection_register)
        activity_register = act_reg.ActivityRegister(
            context.cnv_rules.ExtOperation.EncodeB64MemoryReported)
        ex_dashb = exdb.ExecDashboard(
            ext_connector_starting_time=context.ext_connector_starting_time,
            timeout_ext_conn=context.timeout_ext_conn)

        # Adding the operation context variables in the context for being used by the main thread
        context.add_operation_context_variables(
            connection_register=connection_register,
            activity_register=activity_register,
            todo_list=todo_list,
            exec_dashboard=ex_dashb)

        # Creating the interaction worker and launch it in a new thread
        in_wrker = int_wrkr.InteractionWorker(
            ext_conn_controller=context.ext_conn_controller,
            conversation_rules=context.cnv_rules,
            connection_register=connection_register,
            activity_register=activity_register,
            todo_list=todo_list,
            exec_dashboard=ex_dashb,
            hash_conversation_rules_used=context.hash_conversation_rules_used,
            cleaning_register=context.cleaning_register,
            custom_functions_name=context.custom_functions_name)
        
        new_thread = threading.Thread(
            target=int_wrkr.start_interaction_worker,
            name="InteractionWrkr",
            args=(in_wrker,))
        
        new_thread.start()

        # Start the oversee loop
        oversee_loop(context)
    else:
        logger.error(
            "Connection register not initialised due to Redis connection is not working")


def ending_operation(context):
    '''
    This function is executed to do the required actions to end the operation of 
    the external connector in a graceful way
    '''
    # Sleep a bit to give time to other threads to end its operations
    time.sleep(WAITING_FOR_THREADS_ENDING)
    # Clean temporary files used
    context.cleaning_register.clean_all_temp_files()
    # Inform the engine about the last activities
    send_activities_to_engine(context)
    # Disconnect the external connector from the engine
    eng_com.disconnect_engine(context)


def stop_operation(context):
    '''
    This function triggers the stop signal of the external connector
    '''
    if context.exec_dashboard is not None:
        context.exec_dashboard.end_execution()
