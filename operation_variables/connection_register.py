"""
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega external connector
=================================================
Module: connection_register.py
Author: Alberto Dominguez

This module contains code related to the connection register, and the control of external connections.
This object is threat safe
"""
import copy
import logging
import re
import socket
import threading
import time
from ipaddress import ip_address

import redis
from ext_conn_comms.ext_comm_controller import (CLOSED_SOCKET, MODE_CLIENT,
                                                TRANSPORT_PROTOCOL_UDP)
from utils import connection_utils
from utils.interoperability_py_go import (get_pythonic_value,
                                          interlanguage_bool_check)

from operation_variables import connection

# logger
logger = logging.getLogger(__name__)

# Other Constants
ALL_EXT_CONNECTORS_ID = -1
ALL_CONNECTIONS_ID = 0
DEFAULT_INTERACTION_TIMEOUT = 300
WHEN_RULE_DETECTED = "RULE_DETECTED"
PORT = 1
BAD_FILE_DESCRIPTOR = -1

# DNS resolving constants
FAMILY = 0
TYPE = 1
ADDRESS = 4
IP = 0

# Constant to indicate what kind of memory should be updated
MULTI_EXT_CONNECTORS = "multi_ext_connectors"
GLOBAL_MEMORY = "global"
CONN_MEMORY = "connection"


# ==========================================================================================
# CONNECTION REGISTER
# ==========================================================================================


class ConnectionRegister:
    '''
    Object for modeling the connection register. In essence, it is in-memory storage for
    'Connection' objects, whith the required functions to use it in a structured way
    '''

    def __init__(self, config_ext_conn_timeout, conv_rules_mem_variables, max_concurrent_connections,
                 session_cnfg, op_mode, encoding, close_tcp_after_answering, use_port_as_identifier,
                 interaction_timeout, socket_transport_protocol, session_update_enable,
                 session_update_when, memory_update_when, memory_operations_when, encrypted, custom_function_when, report_memory,
                 custom_function_preprocessor, custom_function_postprocessor, rule_triggered_close_socket,
                 multi_ext_conn_mem_var_enable, redis_ip, redis_port, redis_password, redis_tls, redis_ca_cert,
                 redis_use_client_cert, redis_client_cert, redis_priv_key_protected, redis_priv_key_password,
                 redis_priv_key_client, overwrite_multi_ext_conn_mem_vars_during_init):

        self.register_lock = threading.Lock()
        self.global_memory_lock = threading.Lock()
        self.id_counter = 1
        self.ext_conn_timeout = config_ext_conn_timeout
        self.global_mem_variables = connection_utils.aux_conv_rules_memory_init(
            conv_rules_mem_variables.GlobalLevel,
            ALL_CONNECTIONS_ID)
        self.connection_mem_variables_raw_conn_level = conv_rules_mem_variables.ConnectionLevel
        self.register = dict()
        self.max_concurrent_connections = max_concurrent_connections
        self.active_connections_counter = 0
        self.session_cnfg = session_cnfg
        self.encoding = encoding
        self.encrypted = encrypted

        # Report memory status for each activity?
        self.report_memory = interlanguage_bool_check(report_memory)
        if self.report_memory:
            self.list_mem_vars_to_report = connection_utils.get_mem_var_names_to_report(
                conv_rules_mem_variables)

        # Ext connector mode
        if op_mode.upper() == MODE_CLIENT:
            self.client_mode = True
        else:
            self.client_mode = False

        # Close TCP or DTLS connection after answering (globally, or only rule triggered).
        # If close tcp/dtls mode enable, rule triggered closing is disabled
        self.close_tcp = interlanguage_bool_check(close_tcp_after_answering)
        self.enable_rule_triggered_close_socket = interlanguage_bool_check(
            rule_triggered_close_socket) and not self.close_tcp

        # Use port as part of the identification elements
        self.port_as_identifier = interlanguage_bool_check(
            use_port_as_identifier)

        # UDP protocol?
        self.udp_protocol = socket_transport_protocol.upper() == TRANSPORT_PROTOCOL_UDP

        # Interaction timeout (external session timeout)
        if interaction_timeout > 0:
            self.interaction_timeout = interaction_timeout
        else:
            self.interaction_timeout = None  # Not timeout

        # Memory update, when it should happen
        self.memory_update_when_detected = memory_update_when.upper() == WHEN_RULE_DETECTED

        # Memory operations, when it should happen
        self.memory_operations_when_detected = memory_operations_when.upper() == WHEN_RULE_DETECTED

        # custom function preprocessor
        self.custom_function_preprocessor = custom_function_preprocessor

        # custom function postprocessor
        self.custom_function_postprocessor = custom_function_postprocessor

        # custom function execution, when it should happen
        self.custom_function_when_detected = custom_function_when.upper() == WHEN_RULE_DETECTED

        # Session update functionality
        self.session_update_flag = interlanguage_bool_check(
            session_update_enable.Enable)
        self.session_update_when_detected = session_update_when.upper() == WHEN_RULE_DETECTED

        # To enable the use of Redis server to share memory variables between external connectors
        self.multi_ext_conn_mem_var_enable = interlanguage_bool_check(
            multi_ext_conn_mem_var_enable)

        if self.multi_ext_conn_mem_var_enable:
            self.overwrite_multi_ext_conn_mem_vars_during_init = interlanguage_bool_check(
                overwrite_multi_ext_conn_mem_vars_during_init)

            self.init_redis(redis_use_client_cert, redis_priv_key_protected, redis_priv_key_password,
                            redis_priv_key_client, redis_ip, redis_port, redis_password, redis_tls,
                            redis_ca_cert, redis_client_cert, conv_rules_mem_variables)

        # SessionID caputing RegEx
        if len(self.session_cnfg.EndValue) > 0:
            session_pattern_def = ("(?<=", self.session_cnfg.Key, self.session_cnfg.KeyValueSeparator,
                                   ")(.*?)(?=", self.session_cnfg.EndValue, ")")
        else:
            session_pattern_def = ("(?<=", self.session_cnfg.Key, self.session_cnfg.KeyValueSeparator,
                                   ")(.*?)((?=[ \r\n])|$)")
        session_pattern_string = "".join(session_pattern_def)
        self.session_pattern = re.compile(session_pattern_string)
        logger.info(
            f"Regex for capturing session ID is:'{session_pattern_string}'")

    def init_redis(self, redis_use_client_cert, redis_priv_key_protected, redis_priv_key_password,
                   redis_priv_key_client, redis_ip, redis_port, redis_password, redis_tls, redis_ca_cert,
                   redis_client_cert, conv_rules_mem_variables):
        '''
        Auxiliary method to initialise the redis connection
        '''
        redis_error = False
        if redis_tls and redis_use_client_cert:
            redis_key_file, redis_error = connection_utils.prepare_redis_client_key_file(
                redis_priv_key_protected, redis_priv_key_password, redis_priv_key_client)
            if redis_error:
                logger.error(
                    "Not possible to import the protected redis key for TLS")
            else:
                self.redis = redis.Redis(
                    host=redis_ip, port=redis_port, password=redis_password, ssl=redis_tls,
                    ssl_ca_certs=redis_ca_cert, ssl_certfile=redis_client_cert,
                    ssl_keyfile=redis_key_file)

        elif redis_tls:
            self.redis = redis.Redis(
                host=redis_ip, port=redis_port, password=redis_password, ssl=redis_tls, db=0,
                ssl_ca_certs=redis_ca_cert)
        else:
            self.redis = redis.Redis(
                host=redis_ip, port=redis_port, password=redis_password, db=0)

        if not redis_error:
            # Preparing and initialising the memory variables in the redis server
            multi_ext_conn_mem_prepared = connection_utils.aux_conv_rules_memory_init(
                conv_rules_mem_variables.MultiExtConnLevel, ALL_EXT_CONNECTORS_ID)
            try:
                # check connection
                self.redis_connected = self.redis.ping()
            except Exception as ex:
                self.redis_connected = False
                logger.exception(ex)

            if self.redis_connected:
                self.redis_memory_variables_in_use = dict()
                self.init_multi_ext_conn_mem_prepared(
                    multi_ext_conn_mem_prepared)
        else:
            self.redis_connected = False

    # ==========================================================================================
    # CONTROL METHODS
    # ==========================================================================================

    def max_number_connections_reached(self):
        '''
        Method to know if the max number of connections is reached or not
        '''
        answer = False
        with self.register_lock:
            if self.active_connections_counter >= self.max_concurrent_connections:
                answer = True
        return answer

    def get_new_id(self):
        '''
        Function to get a new connection ID & update 
        the ID counter of the connection register
        '''
        with self.register_lock:
            new_conn_id = self.id_counter
            self.id_counter += 1

        return new_conn_id

    def get_register_copy(self):
        '''
        Method to get a copy of the current status of the register of external connections
        '''
        results = set()
        with self.register_lock:
            for conn in self.register.values():
                results.add(conn.do_copy())

        return results

    def modify_max_concurrent_connections(self, new_max_number_connections):
        '''
        Function to fix a set the maximum number of concurrent connections 
        allowed by the external connector
        '''
        with self.register_lock:
            self.max_concurrent_connections = new_max_number_connections

        logger.debug(f"Modified the max number of concurrent connections," +
                     f" new value:{new_max_number_connections}")

    def check_connection_timers(self):
        '''
        Method to check if the connection timeout is alredy reached in any connection, 
        and if so, mark the connections as timed out
        '''
        now = time.time()
        conns_timed_out = set()

        # If there are positive values as timeout (0 or negative ones mean not timeout)
        with self.register_lock:
            # If interaction timeout is not "nul"/None
            if self.interaction_timeout is not None:
                for conn in self.register.values():
                    # For each open connection in the register
                    if conn.status == connection.ConnectionStatus.OPEN:
                        connection_next_timeout = conn.last_interaction + self.interaction_timeout

                        # if the timeout has been reached, or surpassed
                        if now >= connection_next_timeout:
                            conn.timeout()
                            conns_timed_out.add(conn.do_copy())
                            logger.info(f"Connection:{conn.id} timed out")
            else:
                logger.debug(
                    "No interaction timeout in this execution of external connector")

        return conns_timed_out

    def clean_register(self):
        '''
        Method to remove old connections (closed or timeouts) from the register
        '''
        logger.info("Cleaning the connection register...")

        with self.register_lock:
            for conn_id, conn in self.register.copy().items():

                # For each not open connection in the register (closed or timeout)
                if conn.status != connection.ConnectionStatus.OPEN:
                    self.register.pop(conn_id)
                    logger.debug(
                        f"The connection:{conn.id} was removed from the connection register")

    # ==========================================================================================
    # DETECT & FIND METHODS
    # ==========================================================================================
    def detect_session_id(self, recv_data):
        '''
        Method to detect a session id given an input received from outside
        '''
        regex_results = re.search(self.session_pattern, recv_data)
        if regex_results is not None:
            session_id = regex_results.group()
            logger.info(f"Session ID detected: '{session_id}'")
            if not len(session_id) > 0:
                session_id = None
        else:
            session_id = None
        return session_id

    def find_connections_using_ip(self, source_ip):
        '''
        Method to find a set of connections given an IP and port. 
        It returns a set of copied connections
        '''
        # Check if an IP is an IP and not a domain. Resolve the domain if so
        ip = self.check_ip_or_domain(source_ip)
        results = set()
        with self.register_lock:
            for conn in self.register.values():
                if conn.ip == ip:
                    # get a copy of the connection found
                    results.add(conn.do_copy())
                    logger.debug(f"Found the connection:{conn.id} " +
                                 f"in the connection register for ip:{ip}")
        return results

    def find_active_connection_using_ip(self, source_ip, source_port=None, recv_data=None, connection_socket=None):
        '''
        Method to find an active connection given an IP, port and session_id (within the input received). 
        It only returns one value since only one case should be possible
        '''
        connections = self.find_connections_using_ip(source_ip)
        found_connection = None
        found = False
        port_destination = None

        if recv_data is not None:
            session_id = self.detect_session_id(recv_data)
        else:
            session_id = None

        for conn in connections:
            # Perform checks according to the provided parameters
            status_check_conn_open = conn.status != connection.ConnectionStatus.CLOSE
            session_id_check = conn.session_value == session_id

            if status_check_conn_open:
                # PORT ANALYSIS
                if self.port_as_identifier:
                    port_check = conn.port == source_port
                    # Considered as found if the status is 'OPEN' and; if we use the port as identifier,
                    # it should match or not using the port as identifier and; if the session id is provided,
                    if connection_socket is None:
                        same_socket_port = True  # Nothing to check
                    elif connection_socket.fileno() != CLOSED_SOCKET and\
                            conn.connection_socket.fileno() != BAD_FILE_DESCRIPTOR:
                        port_destination = connection_socket.getsockname()[
                            PORT]
                        same_socket_port = conn.connection_socket.getsockname()[
                            PORT] == port_destination
                    else:
                        same_socket_port = False
                    port_analysis = self.port_as_identifier and port_check and same_socket_port
                else:
                    port_analysis = True

                # SESSION ANALYSIS
                # Case: Not session support enable
                if not conn.session_enable:
                    session_analysis = True  # Nothing to check

                # Cases Group: Session support enable
                # - Case: TCP (client or server) or UDP client or UDP + DTLS
                elif not self.udp_protocol or (self.udp_protocol and self.client_mode) or (self.udp_protocol and self.encrypted):
                    # If sessionID is present, check it. If not, check if the tcp/udp socket is the same (if the socket is open)
                    same_socket_session = conn.connection_socket == connection_socket
                    session_analysis = (
                        conn.session_value is not None) and session_id_check or same_socket_session

                # - Case: UDP server not DTLS
                else:
                    session_analysis = conn.session_value is not None and session_id_check

                # FINAL DECISION
                found = status_check_conn_open and port_analysis and session_analysis
                if found:
                    logger.debug(f"Found the ACTIVE connection:{conn.id} in the connection register" +
                                 f" for the values=> ip:{source_ip}, ports:(source={source_port}, " +
                                 f"destination={port_destination}), and session ID:'{session_id}' (if applicable)")

                    # If DTLS or TCP and close after answer mode => update socket of the connection
                    if ((self.udp_protocol and self.encrypted) or not self.udp_protocol) and (
                            self.close_tcp or (
                                self.enable_rule_triggered_close_socket and (
                                    connection_socket != conn.connection_socket))):
                        found_connection = self.update_connection_socket_and_port_of_a_connection(
                            conn.id, connection_socket, source_port)
                    else:
                        found_connection = conn
                    break
                else:
                    logger.debug(f"The connection:{conn.id} does not match for the values => ip:{source_ip}, port:{source_port}" +
                                 f" and session ID:'{session_id}' (if applicable). Criteria => status_check:" +
                                 f"{status_check_conn_open}, port_analysis:{port_analysis}, session_analysis:{session_analysis}")
            else:
                logger.debug(f"The connection:{conn.id} is not active")

        return found, found_connection, session_id

    def get_active_connections_id(self):
        '''
        Method to get a list of open (active) connections ids
        '''
        results = list()
        with self.register_lock:
            for conn in self.register.values():
                if conn.status != connection.ConnectionStatus.CLOSE:
                    results.append(conn.id)
        return results

    # ==========================================================================================
    # CONNECTION METHODS
    # ==========================================================================================
    def mark_greetings_flag_as_completed(self, conn_id):
        '''
        Method to change the greetings flag of a connection. It returns a flag to indicate it is
        successful or not (if the flag was already mark as completed, it is 'False')
        '''
        success = False
        with self.register_lock:
            if self.register[conn_id].greetings_sent:
                logger.debug(
                    f"Greetings flag of the connection:{conn_id} was already marked")
            else:
                self.register[conn_id].greetings_sent = True
                success = True
                logger.debug(
                    f"Greetings flag of the connection:{conn_id} changed")

        return success

    def touch_connection(self, conn_id):
        '''
        Method to update the 'last_interaction' field of a connection
        '''
        with self.register_lock:
            if conn_id in self.register:
                self.register[conn_id].touch()
            else:
                logger.warning(
                    f"Connection:{conn_id} not found in the connection register")

    def end_connection(self, conn_id):
        '''
        Method to end an active connetion ('logically')
        '''
        with self.register_lock:
            if conn_id in self.register:
                self.register[conn_id].close()
                # Decrease counter of active connections
                self.active_connections_counter -= 1
            else:
                logger.warning(
                    f"Connection:{conn_id} not found in the connection register")

    def timeout_connection(self, conn_id):
        '''
        Method to timeout an active connetion
        '''
        with self.register_lock:
            if conn_id in self.register:
                self.register[conn_id].timeout()
            else:
                logger.warning(
                    f"Connection:{conn_id} not found in the connection register")

    def mark_reconnecting_connection(self, conn_id):
        '''
        Method to mark a connection as reconnecting
        '''
        with self.register_lock:
            if conn_id in self.register:
                self.register[conn_id].mark_reconnecting_status()
            else:
                logger.warning(
                    f"Connection:{conn_id} not found in the connection register")

    def unmark_reconnecting_connection(self, conn_id):
        '''
        Method to timeout an active connetion
        '''
        with self.register_lock:
            if conn_id in self.register:
                self.register[conn_id].unmark_reconnecting_status()
            else:
                logger.warning(
                    f"Connection:{conn_id} not found in the connection register")

    def check_connection_status(self, conn_id):
        '''
        Method to get the connection status of a connection
        '''
        with self.register_lock:
            if conn_id in self.register:
                result = self.register[conn_id].check_status()
            else:
                logger.warning(
                    f"Connection:{conn_id} not found in the connection register")

        return result

    def check_if_any_reconnection_in_progress(self):
        '''
        Method to know if there is any reconnection in progress. 
        '''
        result = False
        if self.client_mode:
            with self.register_lock:
                for conn_id in self.register:
                    status = self.register[conn_id].check_status()
                    result |= status == connection.ConnectionStatus.RECONNECTING
        return result

    def check_ip_or_domain(self, source_ip):
        '''
        Auxiliary method to check if an IP is, indead, an IP and not a domain.
        In case it is a domian, resolve it to get the IP
        '''
        ip_is_ip = True
        ip = None
        try:
            # https://stackoverflow.com/questions/319279/how-to-validate-ip-address-in-python
            # https://docs.python.org/3/library/ipaddress.html#ipaddress.ip_address
            _ = ip_address(source_ip)
        except ValueError:
            ip_is_ip = False

        if ip_is_ip:
            ip = source_ip
        else:
            # It is a domain
            # socket.getaddrinfo() returns a list of 5-tuples with the following structure:
            # (family, type, proto, canonname, sockaddr), where sockaddr is a duple of ip and port
            list_answers = socket.getaddrinfo(source_ip, None)
            for answer in list_answers:
                if (self.udp_protocol and answer[TYPE] == socket.SOCK_DGRAM) or (
                        not self.udp_protocol and answer[TYPE] == socket.SOCK_STREAM):
                    if (answer[FAMILY] == socket.AF_INET) and (len(answer[ADDRESS][IP]) > 0):
                        ip = answer[ADDRESS][IP]
                        break
                    elif (answer[FAMILY] == socket.AF_INET6) and (len(answer[ADDRESS][IP]) > 0):
                        ip = answer[ADDRESS][IP]
                        break
            logger.debug(
                f"Detected domain:{source_ip} and converted into IP:{ip}")
        return ip

    def add_new_connection(self, source_ip, source_port, connection_socket=None, session_value=None,
                           client_socket_id=None):
        '''
        Method to add a new connection in the register. 
        It returns a success flag and a copy of the new connection object
        '''
        # Check if an IP is an IP and not a domain. Resolve the domain if so
        ip = self.check_ip_or_domain(source_ip)

        if connection_socket is None or (
                connection_socket is not None and connection_socket.fileno() != CLOSED_SOCKET):
            # variables to return
            new_conn_id = 0
            if not self.max_number_connections_reached():
                # Create a new connection
                new_conn_id = self.get_new_id()
                now = time.time()
                new_conn = connection.Connection(
                    id_conn=new_conn_id,
                    source_ip=ip,
                    source_port=source_port,
                    mem_variables=self.connection_mem_variables_raw_conn_level,
                    starting_time=now,
                    last_interaction=now,
                    connection_socket=connection_socket,
                    status=connection.ConnectionStatus.OPEN,
                    client_mode=self.client_mode,
                    session_enable=self.session_cnfg.Enable,
                    session_key=self.session_cnfg.Key,
                    session_key_value_separator=self.session_cnfg.KeyValueSeparator,
                    session_end_value=self.session_cnfg.EndValue,
                    session_value_autogenerated=self.session_cnfg.AutoGeneration.Enable,
                    encoding=self.encoding,
                    session_value_numb_chars=self.session_cnfg.AutoGeneration.NumberCharacters,
                    port_as_identifier=self.port_as_identifier,
                    session_value_type_chars=self.session_cnfg.AutoGeneration.CharactersType,
                    session_value=session_value,
                    client_socket_id=client_socket_id)

                # Add it in the register and update the counter of acive connections
                with self.register_lock:
                    self.register[new_conn_id] = new_conn
                    self.active_connections_counter += 1

                logger.info(f"Added a new connection to the connection register with the ID:{new_conn_id}, " +
                            f"with the IP: {ip}, port: {source_port}, and session ID: " +
                            f"{new_conn.session_value}")
                conn_copy = new_conn.do_copy()
            else:
                conn_copy = None
                logger.warning(f"Adding the connection to the register was not possible, max number of " +
                               "active connections reached")
        else:
            conn_copy = None
            logger.warning(
                f"Adding the connection to the register was not possible, socket is closed")

        return conn_copy

    def get_connection_copy(self, connection_id):
        '''
        Method to get a connection copy from the connection register given an ID
        '''
        # Variable to return
        connection_copy = None

        with self.register_lock:
            if connection_id in self.register:
                connection_copy = self.register[connection_id].do_copy()
            else:
                connection_copy = None
                logger.warning(
                    f"Connection ID:{connection_id} not found in the register")
        return connection_copy

    def update_session_id_of_a_connection(self, connection_id, session_value):
        '''
        Method to update a session if of a given connection
        '''
        with self.register_lock:
            if connection_id in self.register:
                self.register[connection_id].update_session_id(session_value)
                connection_copy = self.register[connection_id].do_copy()
            else:
                connection_copy = None
                logger.warning(
                    f"Connection ID:{connection_id} not found in the register")
        return connection_copy

    def update_connection_socket_and_port_of_a_connection(self, connection_id, new_socket, new_port=None):
        '''
        Method to update the connection socket and port of a given connection (if port is provided)
        '''
        with self.register_lock:
            if connection_id in self.register:
                self.register[connection_id].update_connection_socket_and_port(
                    new_socket, new_port)
                connection_copy = self.register[connection_id].do_copy()
            else:
                connection_copy = None
                logger.warning(
                    f"Connection ID '{connection_id}' not found in the register")
        return connection_copy

    def enable_sync_done_async_in_progress_flag_of_a_connection(self, connection_id):
        '''
        Method to enable the flag 'sync_done_async_in_progress' of a given connection ID
        '''
        with self.register_lock:
            if connection_id in self.register:
                self.register[connection_id].enable_sync_done_async_in_progress_flag()
                connection_copy = self.register[connection_id].do_copy()
                logger.debug(
                    f"Flag 'sync_done_async_in_progress' for the connection:{connection_id} enabled")
            else:
                connection_copy = None
                logger.warning(
                    f"Connection ID:{connection_id} not found in the register")
        return connection_copy

    def disable_sync_done_async_in_progress_flag_of_a_connection(self, connection_id):
        '''
        Method to disable the flag 'sync_done_async_in_progress' of a given connection ID
        '''
        with self.register_lock:
            if connection_id in self.register:
                self.register[connection_id].disable_sync_done_async_in_progress_flag()
                connection_copy = self.register[connection_id].do_copy()
                logger.debug(
                    f"Flag 'sync_done_async_in_progress' for the connection:{connection_id} disabled")
            else:
                connection_copy = None
                logger.warning(
                    f"Connection ID:{connection_id} not found in the register")
        return connection_copy

    def check_sync_done_async_in_progress_flag_of_a_connection(self, connection_id):
        '''
        Method to check the flag 'sync_done_async_in_progress' of a given connection ID
        '''
        result = False
        if self.close_tcp or self.enable_rule_triggered_close_socket:
            with self.register_lock:
                if connection_id in self.register:
                    result = self.register[connection_id].check_sync_done_async_in_progress_flag(
                    )
                else:
                    logger.warning(
                        f"Connection ID:{connection_id} not found in the register")
        return result

    def reset_sync_done_async_in_progress_flag_of_a_connection(self, connection_id):
        '''
        Method to reset the flag 'sync_done_async_in_progress' of a given connection ID
        '''
        result = False
        with self.register_lock:
            if connection_id in self.register:
                result = self.register[connection_id].reset_sync_done_async_in_progress_flag(
                )
            else:
                logger.warning(
                    f"Connection ID:{connection_id} not found in the register")
        return result

    def timeout_all_connections(self):
        '''
        Function to end all connections by means of timingout them
        '''
        connection_id_list = self.get_active_connections_id()
        for connecion_id in connection_id_list:
            self.timeout_connection(connecion_id)

    # ==========================================================================================
    # MEMORY METHODS
    # ==========================================================================================
    def get_copy_multi_ext_connectors_memory(self):
        '''
        Method to get a copy of the memory saved in the Redis Server (shared among external connectors)
        '''
        # https://stackoverflow.com/questions/22255589/get-all-keys-in-redis-database-with-python
        multi_ext_conn_mem = None
        if self.multi_ext_conn_mem_var_enable:
            multi_ext_conn_mem = dict()

            for mem_var_name in self.redis_memory_variables_in_use.keys():
                mem_value = self.redis.get(mem_var_name)
                multi_ext_conn_mem[mem_var_name] = get_pythonic_value(
                    self.redis_memory_variables_in_use[mem_var_name],
                    mem_value.decode("utf-8"))

        return multi_ext_conn_mem

    def get_copy_global_memory(self):
        '''
        Method to get a copy of the global memory saved in the register (shared among connections)
        '''
        global_mem = None
        with self.global_memory_lock:
            global_mem = copy.deepcopy(self.global_mem_variables)
        return global_mem

    def get_copy_conn_memory(self, conn_id):
        '''
        Method to get a copy of the memory of a given connection
        '''
        conn_mem = None
        with self.register_lock:
            conn_mem = copy.deepcopy(self.register[conn_id].memory)
        return conn_mem

    def filter_mem_vars_to_be_reported(self, memory):
        '''
        Method to removed those memory variables that should not be reported
        '''
        filtered_memory = dict()
        for mem_var_name, value in memory.items():
            if (mem_var_name in self.list_mem_vars_to_report and
                    self.list_mem_vars_to_report[mem_var_name]):
                filtered_memory[mem_var_name] = value

        return filtered_memory

    def get_copy_of_memory_to_be_reported(self, conn_id):
        '''
        Method to get a copy of all content of the memory
        '''
        global_mem = None
        conn_mem = None
        multi_ext_conn_mem = None
        if self.report_memory:
            global_mem = self.filter_mem_vars_to_be_reported(
                self.get_copy_global_memory())
            if conn_id is not None:
                conn_mem = self.filter_mem_vars_to_be_reported(
                    self.get_copy_conn_memory(conn_id))

            if self.multi_ext_conn_mem_var_enable:
                multi_ext_conn_mem = self.filter_mem_vars_to_be_reported(
                    self.get_copy_multi_ext_connectors_memory())

        return multi_ext_conn_mem, global_mem, conn_mem

    def add_mem_var_to_redis(self, mem_var_name, mem_var_value):
        '''
        Method to add a memory variable in the redis server
        '''
        if type(mem_var_value) is not bool:
            success = self.redis.set(mem_var_name, mem_var_value)
        else:
            success = self.redis.set(mem_var_name, str(mem_var_value))

        return success

    def modify_memory_variable(self, mem_var_name, mem_var_new_value, memory_type,
                               connection_id=None):
        '''
        Method to update a given memory variable using a new value
        '''
        # variable to return,
        success = False

        # For variables saved in the multi external connector memory
        if self.multi_ext_conn_mem_var_enable and (memory_type == MULTI_EXT_CONNECTORS):
            success = self.add_mem_var_to_redis(
                mem_var_name, mem_var_new_value)
            if success:
                logger.info(f"Memory variable '{mem_var_name}' in multi-external connector memory updated. " +
                            f"New value: '{mem_var_new_value}'")
            else:
                logger.warning(f"Memory variable '{mem_var_name}' in multi-external connector memory " +
                               "was not possible to update")

        # For variables saved in the global memory
        elif memory_type == GLOBAL_MEMORY:
            if mem_var_name in self.global_mem_variables:
                with self.global_memory_lock:
                    self.global_mem_variables[mem_var_name] = mem_var_new_value
                success = True
                logger.info(f"Memory variable '{mem_var_name}' in global memory updated. " +
                            f"New value: '{mem_var_new_value}'")
            else:
                logger.warning(
                    f"Variable '{mem_var_name}' not found in the global memory")

        # For the variables saved in the connection memory
        elif (memory_type == CONN_MEMORY) and\
                connection_id is not None and\
                connection_id > 0:
            with self.register_lock:
                success = self.register[connection_id].update_memory(
                    mem_var_name, mem_var_new_value)
        return success

    def init_multi_ext_conn_mem_prepared(self, multi_ext_conn_mem_prepared):
        '''
        Method to initialise the variables fo the multi external connector memory.
        If they are already present, they are not overwritten
        '''
        for mem_name in multi_ext_conn_mem_prepared:
            is_redis_present = self.redis.exists(mem_name)

            # add the memory variable name in the list of memory variables of redis in use
            self.redis_memory_variables_in_use[mem_name] = type(
                multi_ext_conn_mem_prepared[mem_name])

            # Memory variable not present in redis
            if not is_redis_present:
                success = self.add_mem_var_to_redis(
                    mem_name, multi_ext_conn_mem_prepared[mem_name])

                if success:
                    logger.info(
                        f"Memory variable:'{mem_name}' added to the Redis")
                else:
                    logger.warning(
                        f"Not possible to add the memory variable:'{mem_name}' in the Redis")

            # Memory variable present in Redis, but we have to overwrite it
            elif is_redis_present and self.overwrite_multi_ext_conn_mem_vars_during_init:
                success = self.add_mem_var_to_redis(
                    mem_name, multi_ext_conn_mem_prepared[mem_name])
                if success:
                    logger.info(
                        f"Memory variable:'{mem_name}' overwritten in Redis during memory initialization phase")
                else:
                    logger.warning(
                        f"Memory variable:'{mem_name}' was not overwritten in Redis during memory initialization phase")

            # Memory variable present in Redis, and we do not overwrite it
            else:
                logger.info(
                    f"Memory variable:'{mem_name}' already present in the Redis")
