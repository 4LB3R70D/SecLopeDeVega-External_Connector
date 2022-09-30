"""
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega external connector
=================================================
Module: context.py
Author: Alberto Dominguez 

This module contains code related to the context object used by the external conenctor to 
provided a object to store all relevant information for the external connector execution
"""


class ExtConnContext:
    '''
    Object created to store all the variables created in the initialization of the external connector
    '''

    def __init__(self, init_success_flag, ext_conn_config, engine_connected_flag, ext_conn_ID, cnv_rules,
                 ext_conn_controller, max_concurrent_connections, zmq_socket, zmq_context, engine_ip, engine_port,
                 engine_time_out, op_mode, check_time_operation_loop, timeout_ext_conn, ext_conn_secret,
                 engine_encryption, cipher, session_key, nonce, engine_auth_code_blake2b, engine_auth_code_sha_512,
                 ext_connector_starting_time, time_between_interaction_loops, time_between_async_loops,
                 number_async_loops_to_clean_conn_register, restart_waiting_time, time_between_client_sockets_connection,
                 encrypted, initial_delay_client_mode_async_thread, redis_ip, redis_port, redis_password, redis_tls,
                 redis_ca_cert, redis_use_client_cert, redis_client_cert, redis_priv_key_protected, redis_priv_key_password,
                 redis_priv_key_client, hash_conversation_rules_used, cleaning_register, custom_functions_name):

        # Added in the context object creation
        self.init_success_flag = init_success_flag
        self.ext_conn_config = ext_conn_config
        self.engine_connected_flag = engine_connected_flag
        self.ext_conn_ID = ext_conn_ID
        self.cnv_rules = cnv_rules
        self.ext_conn_controller = ext_conn_controller
        self.max_concurrent_connections = max_concurrent_connections
        self.zmq_socket = zmq_socket
        self.zmq_context = zmq_context
        self.engine_ip = engine_ip
        self.engine_port = engine_port
        self.engine_time_out = engine_time_out
        self.op_mode = op_mode
        self.check_time_operation_loop = check_time_operation_loop
        self.timeout_ext_conn = timeout_ext_conn
        self.ext_conn_secret = ext_conn_secret
        self.engine_encryption = engine_encryption
        self.cipher = cipher
        self.session_key = session_key
        self.nonce = nonce
        self.engine_auth_code_blake2b = engine_auth_code_blake2b
        self.engine_auth_code_sha_512 = engine_auth_code_sha_512
        self.ext_connector_starting_time = ext_connector_starting_time
        self.time_between_interaction_loops = time_between_interaction_loops
        self.time_between_async_loops = time_between_async_loops
        self.number_async_loops_to_clean_conn_register = number_async_loops_to_clean_conn_register
        self.restart_waiting_time = restart_waiting_time
        self.time_between_client_sockets_connection = time_between_client_sockets_connection
        self.encrypted = encrypted
        self.initial_delay_client_mode_async_thread = initial_delay_client_mode_async_thread
        self.redis_ip = redis_ip
        self.redis_port = redis_port
        self.redis_password = redis_password
        self.redis_tls = redis_tls
        self.redis_ca_cert = redis_ca_cert
        self.redis_use_client_cert = redis_use_client_cert
        self.redis_client_cert = redis_client_cert
        self.redis_client_cert = redis_client_cert
        self.redis_priv_key_protected = redis_priv_key_protected
        self.redis_priv_key_password = redis_priv_key_password
        self.redis_priv_key_client = redis_priv_key_client
        self.hash_conversation_rules_used = hash_conversation_rules_used
        self.cleaning_register = cleaning_register
        self.custom_functions_name = custom_functions_name

        # Added in the operation of the external socket (they are thread safe)
        self.connection_register = None
        self.activity_register = None
        self.todo_list = None
        self.exec_dashboard = None

    def add_operation_context_variables(self, connection_register, activity_register,
                                        todo_list, exec_dashboard,):
        '''
        Method to add the elements used for the external connector to
        '''
        self.connection_register = connection_register
        self.activity_register = activity_register
        self.todo_list = todo_list
        self.exec_dashboard = exec_dashboard

    def update_ext_conn_context(self, zmq_context, zmq_socket):
        '''
        Method to update the engine connection socket and ZeroMQ context
        '''
        self.zmq_context = zmq_context
        self.zmq_socket = zmq_socket
