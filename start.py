#!~/SecLopeDeVega/sw_external_connector/venv/bin
# -*- coding: utf-8 -*-

"""
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega external connector
=================================================
Module: start.py
Author: Alberto Dominguez

This is the main module that starts the external connector.
It connects with the engine and if successful, start the execution. It uses worker-threads
for interacting with the external agent.
"""

import argparse
import atexit
import configparser
import logging
import os
import signal
import sys
import time
import uuid
from datetime import datetime
from hashlib import blake2b
from logging.handlers import RotatingFileHandler
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import ext_conn_comms.engine_comm_service as eng_comm
import ext_conn_threads.main_thread as main_t
import logic_modules.conversation_module as conv_mod
import utils.cleaning_register as clreg

from ext_conn_comms.ext_comm_controller import (MODE_CLIENT,
                                                init_external_socket)
from operation_variables.context import ExtConnContext
from utils.connection_utils import get_client_socket_id_list
from utils.interoperability_py_go import interlanguage_bool_check

# logger
logger = logging.getLogger()

# Constants
INFINITE_TIME_OUT = "NONE"
EXT_CONN_ID_AUTO_GENERATED = "AUTO"
EXT_CONN_ID_OP_MODE_CLIENT = "CLIENT"
EXT_CONN_ID_OP_MODE_SERVER = "SERVER"
BANNER_COMMAND_LINE_ARGS_KEY_SHORT = "-NB"
BANNER_COMMAND_LINE_ARGS_KEY_LONG = "--nobanner"
BANNER_COMMAND_LINE_ARGS_HELP = "this flag hides the starting banner"
CONFIG_COMMAND_LINE_ARGS_KEY_SHORT = "-CFG"
CONFIG_COMMAND_LINE_ARGS_KEY_LONG = "--config"
CONFIG_COMMAND_LINE_ARGS_HELP = "this option is for specifying an specific configuration file to use"
ID_COMMAND_LINE_ARGS_KEY_SHORT = "-ID"
ID_COMMAND_LINE_ARGS_KEY_LONG = "--ID"
ID_COMMAND_LINE_ARGS_HELP = "this option is for an external connector ID to use"
PASS_COMMAND_LINE_ARGS_KEY_SHORT = "-PWD"
PASS_COMMAND_LINE_ARGS_KEY_LONG = "--password"
PASS_COMMAND_LINE_ARGS_HELP = "this option is for an external connector password(secret) to use"
DEFAULT_CONFIG_FILE = 'ext_conn_config.ini'
MILISECONDS_IN_A_SECOND = 1000
BYTES_IN_A_MB = 1024**2
START_ATTEMPTS = 3
NONE_STRING_FORMAT = "None"

# Config times: (timeout_ext_conn, check_time_operation_loop, engine_time_out, 
# time_between_interaction_loops, time_between_async_loops)
EXT_CONN_TIMEOUT = 0
CHECK_TIME_OPERATION_TIMEOUT = 1
ENGINE_TIMEOUT = 2
TIME_BETWEEN_INTERACTION_LOOPS = 3
TIME_BETWEEN_ASYNC_LOOPS = 4
NUMBER_ASYNC_LOOPS_TO_CLEAN_CONN_REGISTER = 5
RESTART_WAITING_TIME = 6
CLIENT_SOCKETS_TIME = 7
TIME_BETWEEN_CLIENT_SOCKET_CLOSE_CONNECT = 8
DELAY_ASYNC_THREAD = 9



def init_file_logging(config_logging_log_folder, dt_string, logging_formatter,
                      conf_log_prefix, conf_log_extension, rotation=False, 
                      logging_log_rotation_max_size=None,
                      logging_log_rotation_file_number=None, ):
    '''
    This functions configure the logger to provide results in a file (rotation or not)
    '''
    if conf_log_prefix is not None and len(conf_log_prefix) > 0:
        log_prefix = conf_log_prefix
    else:
        log_prefix = "slv_ext_conn_"
    
    if conf_log_extension is not None and len(conf_log_extension) > 0:
        log_extension = conf_log_extension
    else:
        log_extension = ".log"
    
    
    filename_log = os.path.join(
        config_logging_log_folder, log_prefix + dt_string + log_extension)
    if not os.path.isdir(config_logging_log_folder):
        os.makedirs(config_logging_log_folder)

    if not rotation:
        f_handler = logging.FileHandler(filename_log)
        f_handler.setFormatter(logging_formatter)
        logger.addHandler(f_handler)
    else:
        fr_handler = RotatingFileHandler(
            filename_log,
            maxBytes=logging_log_rotation_max_size,
            backupCount=logging_log_rotation_file_number)
        fr_handler.setFormatter(logging_formatter)
        logger.addHandler(fr_handler)


def init_console_logging(logging_formatter):
    '''
    This functions configure the logger to provide results in a file
    '''
    c_handler = logging.StreamHandler()
    c_handler.setFormatter(logging_formatter)
    logger.addHandler(c_handler)


def init_logging(ext_conn_config):
    '''
    This function initialize the logs according the configuration file
    '''
    logging_log_rotation_max_size = 20 * BYTES_IN_A_MB  # MB
    logging_log_rotation_file_number = 5  # log files
    # logging level
    switcher_logging = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    # get current unix timestamp
    now = datetime.now()
    dt_string = now.strftime("%Y_%m_%d-%H_%M_%S")

    # load log config values
    config_logging_level = ext_conn_config['LOGGING']['LEVEL']
    config_logging_log_folder = ext_conn_config['LOGGING']['LOG_FOLDER']
    config_logging_log_mode = ext_conn_config['LOGGING']['LOG_MODE']
    conf_log_prefix  = ext_conn_config['LOGGING']['LOG_PREFIX']
    conf_log_extension  = ext_conn_config['LOGGING']['LOG_EXTENSION']
    
    config_logging_log_rotation_max_size =\
        ext_conn_config['LOGGING']['LOG_ROTATION_MAX_SIZE']
    if ((type(config_logging_log_rotation_max_size) == int) and
            (config_logging_log_rotation_max_size > 0)):
        logging_log_rotation_max_size =\
            config_logging_log_rotation_max_size * BYTES_IN_A_MB

    config_logging_log_rotation_file_number = ext_conn_config[
        'LOGGING']['LOG_ROTATION_FILE_NUMBERS']
    if ((type(config_logging_log_rotation_file_number) == int) and
            (config_logging_log_rotation_file_number > 0)):
        logging_log_rotation_file_number = config_logging_log_rotation_max_size

    logging_level = switcher_logging.get(
        config_logging_level, logging.INFO)

    # prepare logger format
    logging_format = '[%(threadName)s][%(asctime)s][%(levelname)s]: %(message)s'
    date_format = '%y-%m-%d][%H:%M:%S'
    logging_formatter = logging.Formatter(
        fmt=logging_format, datefmt=date_format)

    # Set logger level
    logger.setLevel(logging_level)

    # File logging
    if config_logging_log_mode.upper() == "FILE":
        init_file_logging(config_logging_log_folder, dt_string,
                          logging_formatter, conf_log_prefix, 
                          conf_log_extension)

    # Console and file logging
    elif config_logging_log_mode.upper() == "BOTH":
        init_file_logging(config_logging_log_folder, dt_string,
                          logging_formatter, conf_log_prefix, 
                          conf_log_extension)
        init_console_logging(logging_formatter)

    # File logging with log rotation
    elif config_logging_log_mode.upper() == "FILE_ROTATION":
        init_file_logging(config_logging_log_folder, dt_string,
                          logging_formatter, conf_log_prefix, 
                          conf_log_extension, True,
                          logging_log_rotation_max_size,
                          logging_log_rotation_file_number)

    # Console and file logging with log rotation
    elif config_logging_log_mode.upper() == "BOTH_ROTATION":
        init_file_logging(config_logging_log_folder, dt_string,
                          logging_formatter, conf_log_prefix, 
                          conf_log_extension, True,
                          logging_log_rotation_max_size,
                          logging_log_rotation_file_number)
        init_console_logging(logging_formatter)

    # console logging
    else:
        init_console_logging(logging_formatter)


def get_ext_connector_times(ext_conn_config):
    '''
    Function to get and load the different times used in the external connector
    '''
    # Timeout (seconds) for the external connector, by default (1h)
    timeout_ext_conn = 3600

    # Time (seconds) for main thread operation loop without contacting the engine in case
    # if there is not information to send to the engine. By default => 5s = 5000ms
    check_time_operation_loop = 5000

    # Engine tiemout, by default (5000 ms = 5 seconds)
    engine_time_out = 5000

    # Other times (seconds)
    time_between_interaction_loops = 0.5
    time_between_async_loops = 0.1
    no_async_loops_to_clean_conn_register = 1000
    time_between_client_socket_connection = 0.5
    time_between_client_socket_close_connect = 0.5
    initial_delay_client_mode_async_thread = 3

    # Load engine timeout (500 ms by default)
    config_timeout_engine = int(ext_conn_config['TIMES']['ENGINE_TIME_OUT'])
    if ((type(config_timeout_engine) == int) and
            (config_timeout_engine > 0)):
        engine_time_out = config_timeout_engine * MILISECONDS_IN_A_SECOND
        logger.debug("Default value for engine timeout changed, new value: " +
                     f"{config_timeout_engine}")

    # Load external connector timeout
    config_timeout_ext_connector = ext_conn_config['TIMES']['EXT_CONNECTOR_TIME_OUT']
    if config_timeout_ext_connector == INFINITE_TIME_OUT:
        timeout_ext_conn = None
        logger.debug(
            f"Detected infinite timeout for the execution of the external connector")
    elif (type(config_timeout_ext_connector) == int) and (config_timeout_ext_connector > 0):
        timeout_ext_conn = config_timeout_ext_connector
        logger.debug("Default value for external connector timeout changed, new value: " +
                     f"{config_timeout_ext_connector}")

    # Load sleeping time for the operation loop
    config_check_time_operation_loop = int(
        ext_conn_config['TIMES']['MAIN_THREAD_CHECKING_TIME'])
    if ((type(config_check_time_operation_loop) == int) and (config_check_time_operation_loop > 0)):
        check_time_operation_loop = config_check_time_operation_loop * MILISECONDS_IN_A_SECOND
        logger.debug("Default value for operation loop checking time changed, " +
                     f"new value: {config_check_time_operation_loop}")

    # Load time between interaction thread loops
    config_time_between_interaction_loops = float(
        ext_conn_config['TIMES']['TIME_BETWEEN_INTERACTION_LOOPS'])
    if ((type(config_time_between_interaction_loops) == float) and
            (config_time_between_interaction_loops > 0)):
        time_between_interaction_loops = config_time_between_interaction_loops
        logger.debug("Default value for time between interaction loops changed, " +
                     f"new value: {time_between_interaction_loops}")

    # Load time between async thread loops
    config_time_between_async_loops = float(
        ext_conn_config['TIMES']['TIME_BETWEEN_ASYNC_LOOPS'])
    if ((type(config_time_between_async_loops) == float) and (config_time_between_async_loops > 0)):
        time_between_async_loops = config_time_between_async_loops
        logger.debug("Default value for time between async loops changed, " +
                     f"new value: {time_between_async_loops}")

    # Number of async loops to clean the connection register
    config_no_async_loops_to_clean_conn_register = int(
        ext_conn_config['TIMES']['NUMBER_ASYNC_LOOPS_TO_CLEAN_CONN_REGISTER'])
    if ((type(config_no_async_loops_to_clean_conn_register) == int) and
            (config_no_async_loops_to_clean_conn_register > 0)):
        no_async_loops_to_clean_conn_register = config_no_async_loops_to_clean_conn_register
        logger.debug(
            "Default value for the number of async loops to clean the conn register changed, new value: " +
            f"{no_async_loops_to_clean_conn_register}")

    # Time waiting before restarting
    config_restart_waiting_time = int(
        ext_conn_config['TIMES']['RESTARTING_WAITING_TIME'])
    if ((type(config_restart_waiting_time) == int) and (config_restart_waiting_time > 0)):
        restart_waiting_time = config_restart_waiting_time
        logger.debug("Default value for the ext connector restart waiting time changed, new value: " +
                     f"{restart_waiting_time}")

    # Load time between tcp client connections during startup
    config_time_between_client_socket_connection = float(
        ext_conn_config['TIMES']['TIME_BETWEEN_CLIENT_SOCKET_CONNECTIONS'])
    if ((type(config_time_between_client_socket_connection) == float) and (config_time_between_client_socket_connection > 0)):
        time_between_client_socket_connection = config_time_between_client_socket_connection
        logger.debug("Default value for time between client socket connections changed, " +
                     f"new value: {time_between_client_socket_connection}")

    # Load time between closing a tcp client connection, and reconnect again
    config_time_between_client_socket_close_connection = float(
        ext_conn_config['TIMES']['TIME_BETWEEN_CLIENT_SOCKET_CLOSE_CONNECT'])
    if ((type(config_time_between_client_socket_close_connection) == float) and (config_time_between_client_socket_close_connection > 0)):
        time_between_client_socket_close_connect = config_time_between_client_socket_close_connection
        logger.debug("Default value for time between client socket closing and reconnection changed, " +
                     f"new value: {time_between_client_socket_close_connect}")

    # Load time between closing a tcp client connection, and reconnect again
    config_initial_delay_client_mode_async_thread = float(
        ext_conn_config['TIMES']['TIME_INITIAL_DELAY_ASYNC_THREAD'])
    if ((type(config_initial_delay_client_mode_async_thread) == float) and (config_initial_delay_client_mode_async_thread > 0)):
        initial_delay_client_mode_async_thread = config_initial_delay_client_mode_async_thread
        logger.debug("Default value for initial delay for async thread in client mode changed, " +
                     f"new value: {initial_delay_client_mode_async_thread}")

    return (timeout_ext_conn, check_time_operation_loop, engine_time_out,
            time_between_interaction_loops, time_between_async_loops,
            no_async_loops_to_clean_conn_register, restart_waiting_time,
            time_between_client_socket_connection, time_between_client_socket_close_connect,
            initial_delay_client_mode_async_thread)


def get_ext_conn_credentials(ext_conn_ID, ext_conn_secret_config):
    '''
    function to load and get the external connector credentials
    '''
    # hashing the password for the engine using blake2B
    blake2_manager = blake2b()
    blake2_manager.update(ext_conn_secret_config.encode('utf-8'))
    ext_conn_secret = blake2_manager.hexdigest()

    if ((ext_conn_ID is not None) and (len(ext_conn_ID) > 0) and
            (ext_conn_ID.upper() != EXT_CONN_ID_AUTO_GENERATED)):
        logger.info(f"The current external connector instance has the ID: {ext_conn_ID}. " +
                    "It was loaded from the configuration file")
    else:
        ext_conn_ID = str(hex(uuid.getnode())) + "_" + str(os.getpid())
        logger.info(f"The current external connector instance has the ID: {ext_conn_ID}. " +
                    "This ID was autogenerated")

    return ext_conn_ID, ext_conn_secret


def get_engine_authentication(engine_auth_code_config):
    '''
    function to load and get the authentication elements expected of the engine
    '''
    # hashing the authentication code of the engine using blake2b
    blake2_manager = blake2b()
    blake2_manager.update(engine_auth_code_config.encode('utf-8'))
    engine_auth_code_blake2b = blake2_manager.hexdigest()

    # getting SHA 512
    digest = hashes.Hash(hashes.SHA512())
    digest.update(engine_auth_code_config.encode('utf-8'))
    engine_auth_code_sha_512 = digest.finalize().hex()

    return engine_auth_code_blake2b, engine_auth_code_sha_512


def get_session_encryption():
    '''
    function to create a new Chacha20 key and nonce for encrypting and
    decrypting the messages exchanged with the engine
    https://cryptography.io/en/latest/hazmat/primitives/aead/
    '''
    session_key = ChaCha20Poly1305.generate_key()
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(session_key)

    return cipher, session_key, nonce


def connect_engine_first_time(ext_conn_config, ext_conn_ID, ext_conn_secret, engine_time_out,
                              engine_auth_code_blake2b, engine_auth_code_sha_512):
    '''
    Function to contact with the engine and establish a zeroMQ connection
    '''
    success = True
    engine_encryption = False
    cipher = None
    session_key = None
    nonce = None

    # connecting with the engine
    (success_engine, context, zmq_socket, engine_ip, engine_port) = eng_comm.connect_engine(
        engine_ip=ext_conn_config['NETWORKING']['ENGINE_IP'],
        engine_port=int(ext_conn_config['NETWORKING']['ENGINE_PORT']),
        ext_conn_ID=ext_conn_ID)
    success &= success_engine
    if success_engine:
        success_engine_connection, msg_body, zmq_socket = eng_comm.ping_engine(
            zmq_socket, ext_conn_ID, ext_conn_secret, engine_time_out,
            engine_ip, engine_port, engine_auth_code_blake2b,
            engine_auth_code_sha_512)
        success &= success_engine_connection
        if msg_body != eng_comm.EMPTY_MESSAGE_CONTENT:
            logger.info("Public key received, connection should be encrypted")
            # if something is received in the body of the message, it means the connection should
            # be encrypted and the RSA pub key is received in this field
            engine_encryption = True
            # create CHACHA20 key, and nonce,
            cipher, session_key, nonce = get_session_encryption()
        else:
            logger.info(
                "No public key received, connection will not be encrypted")

    return (success, context, zmq_socket, engine_ip, engine_port, msg_body, engine_encryption,
            cipher, session_key, nonce)


def import_redis_config(ext_conn_config):
    '''
    This function import and verify the values loaded from the configuration file
    '''
    # Initialization of variables
    success = True
    redis_ip = None
    redis_port = None
    redis_password = None
    redis_tls = False
    redis_ca_cert = None
    redis_use_client_cert = False
    redis_client_cert = None
    redis_priv_key_protected = False
    redis_priv_key_password = None
    redis_priv_key_password = None
    redis_priv_key_client = None

    # load raw values
    redis_ip_config = ext_conn_config['REDIS']['REDIS_IP']
    redis_port_config = ext_conn_config['REDIS']['REDIS_PORT']
    redis_password_config = ext_conn_config['REDIS']['REDIS_PASSWORD']
    redis_tls_config = ext_conn_config['REDIS']['REDIS_TLS']
    redis_ca_cert_config = ext_conn_config['REDIS']['REDIS_CA_CERT']
    redis_use_client_cert_config = ext_conn_config['REDIS']['REDIS_USE_CLIENT_CERTIFICATE']
    redis_client_cert_config = ext_conn_config['REDIS']['REDIS_CA_CERT']
    redis_priv_key_protected_config = ext_conn_config['REDIS']['REDIS_PRIV_KEY_CLIENT_PROTECTED']
    redis_priv_key_password_config = ext_conn_config['REDIS']['REDIS_PRIV_KEY_PASSWORD']
    redis_priv_key_client_config = ext_conn_config['REDIS']['REDIS_PRIV_KEY_CLIENT']

    # IP or host check
    if len(redis_ip_config) > 0:
        redis_ip = redis_ip_config
    else:
        success &= False

    # Port check
    try:
        redis_port = int(redis_port_config)
    except ValueError as ex:
        success &= False
        logger.exception("Redis port value is not an int", ex)

    # Bool transformation of TLS flag and use of client certificate
    redis_tls = redis_tls_config.upper() == "YES"
    redis_use_client_cert = redis_use_client_cert_config.upper() == "YES"
    redis_priv_key_protected = redis_priv_key_protected_config.upper() == "YES"

    # this fields not need of checks (optional ones)
    if redis_password_config is not None and len(redis_password_config) > 0:
        redis_password = redis_password_config
    if redis_ca_cert_config is not None and len(redis_ca_cert_config) > 0:
        redis_ca_cert = redis_ca_cert_config
    if redis_client_cert_config is not None and len(redis_client_cert_config) > 0:
        redis_client_cert = redis_client_cert_config
    if redis_priv_key_password_config is not None and len(redis_priv_key_password_config) > 0:
        redis_priv_key_password = redis_priv_key_password_config
    if redis_priv_key_client_config is not None and len(redis_priv_key_client_config) > 0:
        redis_priv_key_client = redis_priv_key_client_config

    return success, (redis_ip, redis_port, redis_password, redis_tls, redis_ca_cert, redis_use_client_cert,
                     redis_client_cert, redis_priv_key_protected, redis_priv_key_password, redis_priv_key_client)


def init_external_connector(init_logging_flag, arg_config_file, arg_ext_conn_ID, arg_ext_conn_secret):
    '''
    This function is the one in charge of initialising the external connector for operation
    It returns a valaue about the success of the operation and the external listening socket,
    as well other relevant variables    '''
    print("Loading configuration file...")
    # load configuration
    ext_conn_config = configparser.ConfigParser()
    if (arg_config_file is None or
            len(os.path.basename(arg_config_file)) <= 1):
        ext_conn_config.read(DEFAULT_CONFIG_FILE)
    else:
        ext_conn_config.read(arg_config_file)
    print("Configuration file parsed!")

    if init_logging_flag:
        # init logging
        print("Starting logging capabilities...")
        init_logging(ext_conn_config)
        init_logging_flag = False

    print("Logging working! from now on all execution information will be provided via logs")
    logger.debug('External connector logging working!')

    # get different times used in the external connector
    ext_conn_times = get_ext_connector_times(ext_conn_config)

    # If external connector ID and passwords are provided as command line interface arguments, use them
    if arg_ext_conn_ID is not None and len(arg_ext_conn_ID) > 0 and arg_ext_conn_ID != NONE_STRING_FORMAT:
        ext_conn_ID_config = arg_ext_conn_ID
    else:
        ext_conn_ID_config = ext_conn_config['OPERATION']['EXTERNAL_CONNECTOR_ID']

    if arg_ext_conn_secret is not None and len(arg_ext_conn_secret) > 0 and arg_ext_conn_ID != NONE_STRING_FORMAT:
        ext_conn_secret_config = arg_ext_conn_secret
    else:
        ext_conn_secret_config = ext_conn_config['OPERATION']['EXTERNAL_CONNECTOR_SECRET']

    # create an ID for the current instance and secret
    ext_conn_ID, ext_conn_secret = get_ext_conn_credentials(
        ext_conn_ID=ext_conn_ID_config,
        ext_conn_secret_config=ext_conn_secret_config)

    # loading Engine authentication (hash blake2b and sha-512)
    engine_auth_code_blake2b, engine_auth_code_sha_512 = get_engine_authentication(
        engine_auth_code_config=ext_conn_config['OPERATION']['ENGINE_AUTH_CODE'])

    # =======================================================================================
    # Starting the main components of the external connector
    # =======================================================================================
    ext_conn_context = None
    try:
        success, context, zmq_socket, engine_ip, engine_port, msg_body,\
            engine_encryption, cipher, session_key, nonce = connect_engine_first_time(
                ext_conn_config, ext_conn_ID, ext_conn_secret, ext_conn_times[ENGINE_TIMEOUT],
                engine_auth_code_blake2b, engine_auth_code_sha_512)
        cnv_rules = None

        if success:
            engine_connected = True
            # load conversation rules
            (success_cnv_rules, cnv_rules, zmq_socket,
             hash_conversation_rules_used) = conv_mod.get_conversation_rules(
                success=success,
                ext_conn_ID=ext_conn_ID,
                engine_encryption=engine_encryption,
                ext_conn_secret=ext_conn_secret,
                engine_time_out=ext_conn_times[ENGINE_TIMEOUT],
                zmq_socket=zmq_socket,
                engine_ip=engine_ip,
                engine_port=engine_port,
                rsa_key=msg_body,
                session_key=session_key,
                session_cipher=cipher,
                nonce=nonce,
                engine_auth_code_blake2b=engine_auth_code_blake2b,
                engine_auth_code_sha_512=engine_auth_code_sha_512)
            success &= success_cnv_rules
            if success:
                logger.info(f"Conversation rules loaded successfully. Name: '{cnv_rules.Name}', " +
                            f"using port:'{cnv_rules.ExtOperation.Port}' in mode:'{cnv_rules.ExtOperation.Mode}' " +
                            f"and transport protocol:'{cnv_rules.ExtOperation.TransportProtocol}'. " +
                            f"Encryption enable? {cnv_rules.ExtOperation.Encrypted}")

                if cnv_rules.ExtOperation.Mode.upper() == MODE_CLIENT:
                    socket_id_list = get_client_socket_id_list(
                        cnv_rules.ExtOperation.MaxConcurrentConnections)
                else:
                    socket_id_list = None

                cleaning_register = clreg.CleaningRegister()

                # starting external socket using the input received from the engine
                (success, ext_conn_controller) = init_external_socket(
                    ip=cnv_rules.ExtOperation.IP,
                    port=cnv_rules.ExtOperation.Port,
                    mode=cnv_rules.ExtOperation.Mode,
                    transport_protocol=cnv_rules.ExtOperation.TransportProtocol,
                    config_max_input_bytes=cnv_rules.ExtOperation.MaxInputSize,
                    config_max_connections_queue=cnv_rules.ExtOperation.ConnectionQueue,
                    use_ip6=cnv_rules.ExtOperation.UseIP6,
                    encrypted=cnv_rules.ExtOperation.Encrypted,
                    tls_client_default_settings=ext_conn_config['D/TLS']['CLIENT_DEFAULT_SETTINGS'],
                    tls_client_cabundle_pem=ext_conn_config['D/TLS']['CLIENT_CABUNDLE_PEM'],
                    tls_server_certchain_pem=ext_conn_config['D/TLS']['SERVER_CERTCHAIN_PEM'],
                    tls_server_priv_key_pem=ext_conn_config['D/TLS']['SERVER_PRIV_KEY_PEM'],
                    tls_key_protected=ext_conn_config['D/TLS']['KEY_PROTECTED'],
                    tls_server_key_password=ext_conn_config['D/TLS']['SERVER_KEY_PASSWORD'],
                    tls_validate_server_certificate=ext_conn_config[
                        'D/TLS']['CLIENT_VALIDATE_SERVER_CERTIFICATE'],
                    tls_client_authentication=cnv_rules.ExtOperation.TlsClientAuthentication,
                    num_client_conns=cnv_rules.ExtOperation.MaxConcurrentConnections,
                    listening_time=ext_conn_times[TIME_BETWEEN_INTERACTION_LOOPS],
                    socket_id_list=socket_id_list,
                    time_between_client_sockets_connection=ext_conn_times[CLIENT_SOCKETS_TIME],
                    dtls_mode=ext_conn_config['D/TLS']['DTLS_VERSION'],
                    time_between_client_socket_close_connect=ext_conn_times[
                        TIME_BETWEEN_CLIENT_SOCKET_CLOSE_CONNECT],
                    tls_client_certchain_pem=ext_conn_config['D/TLS']['CLIENT_CERTCHAIN_PEM'],
                    tls_client_priv_key_pem=ext_conn_config['D/TLS']['CLIENT_PRIV_KEY_PEM'],
                    tls_client_key_password=ext_conn_config['D/TLS']['CLIENT_KEY_PASSWORD'],
                    cleaning_register=cleaning_register)

                # Import custom functions module
                custom_functions_directory = ext_conn_config['OPERATION']['CUSTOM_FUNCTIONS_DIRECTORY']
                custom_functions_name = ext_conn_config['OPERATION']['CUSTOM_FUNCTIONS_MODULE_NAME']
                custom_functions_file_name = custom_functions_name+".py"
                custom_function_file_path = os.path.join(
                    custom_functions_directory,
                    custom_functions_file_name)
                custom_function_path_exists = os.path.exists(
                    custom_function_file_path)
                # https://www.codegrepper.com/code-examples/python/python+import+from+other+folder
                if custom_functions_directory is not None and custom_function_path_exists:
                    sys.path.append(custom_functions_directory)
                    logger.info(
                        "Custom functions directory imported successfully")
                else:
                    logger.warning(
                        "Custom function directory not imported, it is not a valid directory")

                # Redis initialization
                redis_ip = None
                redis_port = None
                redis_password = None
                redis_tls = None
                redis_ca_cert = None
                redis_use_client_cert = None
                redis_client_cert = None
                redis_priv_key_protected = None
                redis_priv_key_password = None
                redis_priv_key_client = None
                success_redis_config, (
                    redis_ip, redis_port, redis_password, redis_tls, redis_ca_cert,
                    redis_use_client_cert, redis_client_cert, redis_priv_key_protected,
                    redis_priv_key_password, redis_priv_key_client) = import_redis_config(ext_conn_config)

                # not multiexternal connector memory enable, or it is enabled and the configuration is loaded successfully
                if not interlanguage_bool_check(cnv_rules.ExtOperation.MemVarMultiExtConnEnable) or (
                        success_redis_config and interlanguage_bool_check(
                            cnv_rules.ExtOperation.MemVarMultiExtConnEnable)):
                    # build a context object to return
                    ext_conn_context = ExtConnContext(
                        init_success_flag=success,
                        ext_conn_config=ext_conn_config,
                        engine_connected_flag=engine_connected,
                        ext_conn_ID=ext_conn_ID,
                        cnv_rules=cnv_rules,
                        ext_conn_controller=ext_conn_controller,
                        max_concurrent_connections=cnv_rules.ExtOperation.MaxConcurrentConnections,
                        zmq_socket=zmq_socket,
                        zmq_context=context,
                        engine_ip=engine_ip,
                        engine_port=engine_port, engine_time_out=ext_conn_times[ENGINE_TIMEOUT],
                        op_mode=cnv_rules.ExtOperation.Mode,
                        check_time_operation_loop=ext_conn_times[CHECK_TIME_OPERATION_TIMEOUT],
                        timeout_ext_conn=ext_conn_times[EXT_CONN_TIMEOUT],
                        ext_conn_secret=ext_conn_secret,
                        engine_encryption=engine_encryption,
                        cipher=cipher,
                        session_key=session_key,
                        nonce=nonce,
                        engine_auth_code_blake2b=engine_auth_code_blake2b,
                        engine_auth_code_sha_512=engine_auth_code_sha_512,
                        ext_connector_starting_time=time.time(),
                        time_between_interaction_loops=ext_conn_times[TIME_BETWEEN_INTERACTION_LOOPS],
                        time_between_async_loops=ext_conn_times[TIME_BETWEEN_ASYNC_LOOPS],
                        number_async_loops_to_clean_conn_register=ext_conn_times[
                            NUMBER_ASYNC_LOOPS_TO_CLEAN_CONN_REGISTER],
                        restart_waiting_time=ext_conn_times[RESTART_WAITING_TIME],
                        time_between_client_sockets_connection=ext_conn_times[CLIENT_SOCKETS_TIME],
                        encrypted=ext_conn_controller.encrypted,
                        initial_delay_client_mode_async_thread=ext_conn_times[DELAY_ASYNC_THREAD],
                        redis_ip=redis_ip,
                        redis_port=redis_port,
                        redis_password=redis_password,
                        redis_tls=redis_tls,
                        redis_ca_cert=redis_ca_cert,
                        redis_use_client_cert=redis_use_client_cert,
                        redis_client_cert=redis_client_cert,
                        redis_priv_key_protected=redis_priv_key_protected,
                        redis_priv_key_password=redis_priv_key_password,
                        redis_priv_key_client=redis_priv_key_client,
                        hash_conversation_rules_used=hash_conversation_rules_used,
                        cleaning_register=cleaning_register,
                        custom_functions_name=custom_functions_name)
                else:
                    success = False
                    logger.warning("Incorrect Redis configuration!")
            else:
                ext_conn_context = None
                engine_connected = False
                logger.warning('Conversation rules cannot be obtained!')
        else:
            ext_conn_context = None
            logger.warning('Engine is not connected!')
    except Exception as ex:
        ext_conn_context = None
        success = False
        logger.exception(ex)

    return ext_conn_context, init_logging_flag


def banner():
    '''
    This function prints the starting banner
    '''
    print("***************************************************************************************************************************************************************************************")
    print("")
    print("***************************************************************************************************************************************************************************************")
    print("")
    print("      *******                                ***** *                                          ***** **                     ***** *      **                                             ")
    print("    *       ***                           ******  *                                        ******  ***                  ******  *    *****                                             ")
    print("   *         **                          **   *  *                                       **    *  * ***                **   *  *       *****                                           ")
    print("   **        *                          *    *  *                                       *     *  *   ***              *    *  **       * **                                            ")
    print("    ***                                     *  *             ****     ****                   *  *     ***                 *  ***      *                                                ")
    print("   ** ***           ***       ****         ** **            * ***  * * ***  *  ***          ** **      **    ***         **   **      *   ***       ****      ****                     ")
    print("      *** ***     *   ***   *   ****       ** **          **    ** **    **  *   ***        ** **      **  *   ***       **   **     *  *   ***   *    **** *   ****                   ")
    print("        *** ***  **    *** **              ** **          **    ** **    ** **    ***       ** **      ** **    ***      **   **     * **    *** **     ** **    **                    ")
    print("          ** *** ********  **              ** **          **    ** **    ** ********        ** **      ** ********       **   **     * ********  **     ** **    **                    ")
    print("           ** ** *******   **              *  **          **    ** **    ** *******         *  **      ** *******         **  **    *  *******   **     ** **    **                    ")
    print("            * *  **        **                 *           **    ** **    ** **                 *       *  **               ** *     *  **        **     ** **    **                    ")
    print("  ***        *   ****    * ***     *      ****           * ******  *******  ****    *     *****       *   ****    *         ***     *  ****    * **     ** **    **                    ")
    print(" *  *********     *******   *******      *  *************   ****   ******    *******     *   *********     *******           *******    *******   ********  ***** **                   ")
    print("*     *****        *****     *****      *     *********            **         *****     *       ****        *****              ***       *****      *** ***  ***   **                  ")
    print("*                                       *                          **                   *                                                                ***                           ")
    print(" **                                      **                        **                    **                                                        ****   ***                          ")
    print("                                                                    **                                                                           *******  **                           ")
    print("                                                                                                                                                *     ****                             ")
    print("                                                                                                                                                                                       ")
    print("                                                                                                                                                                                       ")
    print("     ***** **                                                                ***             * ***                                                                                     ")
    print("  ******  **** *                  *                                           ***          *  ****  *                                                        *                         ")
    print(" **   *  * ****                  **                                            **         *  *  ****                                                        **                         ")
    print("*    *  *   **                   **                                            **        *  **   **                                                         **                         ")
    print("    *  *         ***    ***    ********     ***  ****                          **       *  ***          ****                                              ******** ****   ***  ****    ")
    print("   ** **        * ***  **** * ******** ***   **** **** * ***  ****     ****    **      **   **         * ***  * ***  ****   ***  ****     ***       **** ******** * ***  * **** **** * ")
    print("   ** **           *** *****     **   * ***   **   ****   **** **** * * ***  * **      **   **        *   ****   **** **** * **** **** * * ***     * ***  * **   *   ****   **   ****  ")
    print("   ** ******        ***  **      **  *   ***  **           **   **** *   ****  **      **   **       **    **     **   ****   **   **** *   ***   *   ****  **  **    **    **         ")
    print("   ** *****          ***         ** **    *** **           **    ** **    **   **      **   **       **    **     **    **    **    ** **    *** **         **  **    **    **         ")
    print("   ** **            * ***        ** ********  **           **    ** **    **   **      **   **       **    **     **    **    **    ** ********  **         **  **    **    **         ")
    print("   *  **           *   ***       ** *******   **           **    ** **    **   **       **  **       **    **     **    **    **    ** *******   **         **  **    **    **         ")
    print("      *           *     ***      ** **        **           **    ** **    **   **        ** *      * **    **     **    **    **    ** **        **         **  **    **    **         ")
    print("  ****         * *       *** *   ** ****    * ***          **    ** **    **   **         ***     *   ******      **    **    **    ** ****    * ***     *  **   ******     ***        ")
    print(" *  *********** *         ***     ** *******   ***         ***   *** ***** **  *** *       *******     ****       ***   ***   ***   *** *******   *******    **   ****       ***       ")
    print("*     ******                          *****                 ***   *** ***   **  ***          ***                   ***   ***   ***   *** *****     *****                               ")
    print("*                                                                                                                                                                                      ")
    print(" **                                                                                                                                                                                    ")
    print("                                                                                                                                                                                       ")
    print("***************************************************************************************************************************************************************************************")
    print("")
    print("***************************************************************************************************************************************************************************************")
    print("VERSION: 0.5")
    print("")
    print("")
    print("STARTING EXECUTION...")


def manage_external_connector_initialization(config, ext_conn_ID, ext_conn_secret):
    '''
    Function to try to manage an external connector initialization and potential interruptions
    '''
    # Try to start several times
    attempts = 0
    success = False
    init_logging_flag = True

    while (attempts < START_ATTEMPTS) and not success:
        # initialising the external connector
        context, init_logging_flag = init_external_connector(
            init_logging_flag, config, ext_conn_ID, ext_conn_secret)
        if context is not None:
            success = context.init_success_flag
        else:
            logger.error(
                f"Starting the external connector failed, trying again. Attempt: {attempts+1}/3")
        attempts += 1

    def end():
        '''
        Function to end gracefully the execution of the external connector
        https://stackoverflow.com/questions/12371361/using-variables-in-signal-handler-require-global
        '''
        main_t.stop_operation(context)
        main_t.ending_operation(context)
        sys.exit()

    if success:
        # prepare the external connector to end gracefully in case of OS signal received
        signal.signal(signal.SIGTERM, end)

        try:
            main_t.start_operation(context)
            # ending operation
            main_t.ending_operation(context)

            # restart?
            if context.exec_dashboard.check_restart_flag():
                logger.info(
                    f"Scheduled external connector reboot after {context.restart_waiting_time} seconds...")
                time.sleep(context.restart_waiting_time)
                logger.info(
                    f"EXTERNAL CONNECTION RESTART! Here we go again!\n\n")
                main()

        except KeyboardInterrupt:
            logger.warning("Detected Control+C keys, ending execution...")
            end()

        except InterruptedError:
            logger.warning(
                "Interrruption error 'SIGINT' received, ending execution...")
            end()

    else:
        logger.critical('Starting the external connector was not possible, ' +
                        'please check the logs to get more information. Ending execution...')


# =====================================================================================================
#                                    EXT CONNECTOR STARTING POINT
# =====================================================================================================


def main():
    '''
    This function is the first called in the execution of the external connector
    It starts connecting with the engine, if no success, the process is finished
    (no external connector without control)
    '''
    # https://docs.python.org/3/howto/argparse.html
    # https://realpython.com/python-command-line-arguments/
    parser = argparse.ArgumentParser()
    parser.add_argument(BANNER_COMMAND_LINE_ARGS_KEY_SHORT, BANNER_COMMAND_LINE_ARGS_KEY_LONG,
                        help=BANNER_COMMAND_LINE_ARGS_HELP, action='store_true')
    parser.add_argument(CONFIG_COMMAND_LINE_ARGS_KEY_SHORT, CONFIG_COMMAND_LINE_ARGS_KEY_LONG,
                        help=CONFIG_COMMAND_LINE_ARGS_HELP, type=Path)
    parser.add_argument(ID_COMMAND_LINE_ARGS_KEY_SHORT, ID_COMMAND_LINE_ARGS_KEY_LONG,
                        help=ID_COMMAND_LINE_ARGS_HELP, type=str, dest="ext_conn_ID")
    parser.add_argument(PASS_COMMAND_LINE_ARGS_KEY_SHORT, PASS_COMMAND_LINE_ARGS_KEY_LONG,
                        help=PASS_COMMAND_LINE_ARGS_HELP, type=str, dest="ext_conn_secret")
    args = parser.parse_args()

    # print the banner
    if not args.nobanner:
        banner()

    # try to initialise the external conenctor
    manage_external_connector_initialization(
        args.config, args.ext_conn_ID, args.ext_conn_secret)


def exit_handler():
    logger.warning("\n\n..........EXECUTION ENDED..........\n\n")


atexit.register(exit_handler)

# start the execution
if __name__ == "__main__":
    main()
