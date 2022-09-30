"""
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega external connector
=================================================
Module: async_worker.py
Author: Alberto Dominguez 

This module contains the business logic of async thread, which oversees the async tasks and controls the timings.
It does the following:
    1 - external connector time out (end execution)
    2 - connections timeout ("session timeout for external connections")
    3 - check ASYNC rules to execute
    4 - create an operation worker to execute the async tasks
"""
import logging
import threading
import time

from ext_conn_threads import operation_loops as op_loops
from ext_conn_threads import operation_worker as op_wrkr


# logger
logger = logging.getLogger(__name__)


def get_initial_async_delay(initial_delay_client_mode_async_thread, time_between_async_loops):
    '''
    Auxiliary method to get the initial async delay for clients connections
    '''
    now = time.time()
    initial_async_delay = now + \
        initial_delay_client_mode_async_thread + time_between_async_loops

    return initial_async_delay


def run_async_worker(exec_dashboard, connection_register, todo_list, cnv_rules, activity_register,
                     ext_conn_controller, time_between_async_loops, number_async_loops_to_clean_conn_register,
                     initial_delay_client_mode_async_thread, hash_conversation_rules_used, cleaning_register,
                     custom_functions_name):
    '''
    This function is the main one for operation for the main thread, controlling the execution
    of the external connector
    '''
    # after 100 loops, clean the connection register
    cleaning_conn_register_counter = 0
    initial_async_delay = get_initial_async_delay(
        initial_delay_client_mode_async_thread, time_between_async_loops)

    # Background loop 
    while (exec_dashboard.check_execution_flag()):

        if ext_conn_controller.client_mode:
            if not exec_dashboard.is_interaction_started():
                initial_async_delay = get_initial_async_delay(
                    initial_delay_client_mode_async_thread, time_between_async_loops)

            # 0 - if client mode, check if all connections are still alive. If not, end execution.
            else:
                now = time.time()
                # It only checks connections when there is no active connections after an initial delay in client mode
                # to give time for client connections to be established.
                if now > initial_async_delay:
                    # Check client connections status
                    list_active_connections_id = connection_register.get_active_connections_id()
                    if len(list_active_connections_id) == 0:
                        logger.info(
                            "All client sockets are not active, execution should be finished")
                        exec_dashboard.end_execution()

        # 1 - check execution timeout
        if exec_dashboard.reached_execution_timeout():
            exec_dashboard.end_execution()
            logger.warning(
                "External connector execution timeout reached. Execution will be ended")

        # 2 - check connection time outs and conn register cleaning
        conns_timed_out = connection_register.check_connection_timers()
        if cleaning_conn_register_counter >= number_async_loops_to_clean_conn_register:
            connection_register.clean_register()
            cleaning_conn_register_counter = 0
        else:
            cleaning_conn_register_counter += 1

        # 3 - get ToDos to execute (async tasks)
        todos_to_do = todo_list.get_todos_to_execute()

        # If there is something to do
        if len(conns_timed_out) > 0 or len(todos_to_do) > 0:
            # Creating an operation worker and launching it in a new thread for doing the async tasks
            op_wrker = op_wrkr.OperationWorker(
                conversation_rules=cnv_rules,
                connection_register=connection_register,
                activity_register=activity_register,
                todo_list=todo_list,
                exec_dashboard=exec_dashboard,
                ext_conn_controller=ext_conn_controller,
                hash_conversation_rules_used=hash_conversation_rules_used,
                cleaning_register=cleaning_register,
                custom_functions_name=custom_functions_name)

            new_thread = threading.Thread(
                target=op_loops.async_loop,
                name=op_wrker.thread_name,
                kwargs={'op_wrker': op_wrker,
                        'conns_timed_out': conns_timed_out,
                        'todos_to_do': todos_to_do},)
            new_thread.start()

        # Time before starting a new loop
        time.sleep(time_between_async_loops)

    else:
        logger.warn("Async worker stopped!")
