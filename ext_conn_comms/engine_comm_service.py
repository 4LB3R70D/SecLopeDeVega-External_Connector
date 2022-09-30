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
Module: engine_comm_service.py
Author: Alberto Dominguez 

This is the one in charge of controlling the communication with the engine:
    - starting it
    - sending information to it
    - get potential orders
    - ending the communication
    - preparing the messages to be sent
"""

import base64
import json
import logging
import random
import time
from enum import Enum
from ipaddress import IPv4Address, ip_address

import zmq
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# logger
logger = logging.getLogger(__name__)

# ==========================================================================================
# ZeroMQ Connection
# ==========================================================================================
REQUEST_RETRIES = 5
# Wait before disconnect
WAIT_BEFORE_DISCONNECT = 3  # seconds
'''
https://pyzmq.readthedocs.io/en/latest/
https://zguide.zeromq.org/
'''

def check_engine_ip (engine_ip):
    '''
    This function checks if a provided engine IP is valid, and if it is ipv4 or ipv6
    '''
    ip_valid = False
    ip6 = False
    if (engine_ip is not None and
        len(engine_ip) > 0): 
        ip_valid = True
        ip6 = False if type(ip_address(engine_ip)) is IPv4Address else True
    
    return ip_valid, ip6


def connect_engine(engine_ip, engine_port, ext_conn_ID, zmq_context=None):
    '''
    This function establishes a Request- Response connection with the engine
    '''
    # Successful flag
    success_engine = False
    ip_valid = False
    ip6 = False
    zmq_socket = None
    
    try:
        ip_valid, ip6 = check_engine_ip (engine_ip)
    except ValueError:
        logger.error("Invalid engine IP")

    # check if values are not 'null' and the port is an integer
    if  ip_valid and (
        engine_port is not None) and (
            type(engine_port) == int):
        # check if an existing zmq context is passed as parameter
        # if not, it creates a new onw
        if not zmq_context:
            zmq_context = zmq.Context()
        # https://zguide.zeromq.org/docs/chapter3/#The-Asynchronous-Client-Server-Pattern
        zmq_socket = zmq_context.socket(zmq.DEALER)
        zmq_socket.identity = ext_conn_ID.encode('utf-8')
        zmq_socket.setsockopt(zmq.IPV6, ip6);
        zmq_socket.connect(f'tcp://{engine_ip}:{engine_port}')
        success_engine = True
    else:
        logger.warning(
            "Invalid engine IP or port values")

    return (success_engine, zmq_context, zmq_socket, engine_ip, engine_port)


def reset_engine_connection(ext_conn_context=None, v_zmq_socket=None,
                            v_engine_ip=None, v_engine_port=None,
                            v_ext_conn_ID=None):
    '''
    auxiliary function to close and open the connection with the engine. 
    It uses either the context object, or  the values ('v_') it needs directly. 
    If context is passed, then variables are not used
    '''

    # create a local variables that refers to the corresponding
    # values used in the function
    if ext_conn_context is not None:
        local_zmq_socket = ext_conn_context.zmq_socket
        local_engine_ip = ext_conn_context.engine_ip
        local_engine_port = ext_conn_context.engine_port
        local_ext_conn_ID = ext_conn_context.ext_conn_ID
        local_zmq_context = ext_conn_context.zmq_context

    else:
        local_zmq_socket = v_zmq_socket
        local_engine_ip = v_engine_ip
        local_engine_port = v_engine_port
        local_ext_conn_ID = v_ext_conn_ID
        local_zmq_context = None

    # Close connection
    local_zmq_socket.setsockopt(zmq.LINGER, 0)
    local_zmq_socket.close()

    # Reconnect
    return connect_engine(local_engine_ip, local_engine_port,
                          local_ext_conn_ID, local_zmq_context)


def receive_messages_from_engine(zmq_socket, engine_time_out):
    '''
    Function to get messages sent from the engine
    '''
    zmq_poller = zmq.Poller()
    zmq_poller.register(zmq_socket, zmq.POLLIN)
    msg_received = False
    reply = None

    sockets = dict(zmq_poller.poll(engine_time_out))

    if zmq_socket in sockets:
        reply = zmq_socket.recv()
        # Reply received ==> successful delivery
        if reply and (len(reply) > 0):
            msg_received = True
            logger.debug("Message received from the engine")

    return msg_received, reply


def zeromq_message_delivery(msg, zmq_socket, engine_ip, engine_port,
                            engine_time_out, ext_conn_ID, ext_conn_context=None):
    '''
    This function allows sending data to the engine (low level function), 
    it manages directly the ZeroMQ functions to send the message and get a reply
    '''
    reply = ""
    retries_left = REQUEST_RETRIES
    delivered = False

    # try to send the message (3 attempts)
    while((retries_left > 0) and not delivered):

        # sending the message & wait a bit for getting a response
        zmq_socket.send_string(msg)
        wait_time = random.uniform(
            MIN_WAITING_TIME_FOR_ENGINE_BUSY,
            MAX_WAITING_TIME_FOR_ENGINE_BUSY)
        time.sleep(wait_time)

        # get the response
        msg_received, reply = receive_messages_from_engine(
            zmq_socket, engine_time_out)
        # message received?
        if msg_received:
            delivered = msg_received
            logging.debug(f"Response received after sending a message to " +
                          f"the engine. Retries left = {retries_left}")

        else:
            retries_left -= 1
            logging.info(
                "Not response received, reseting the connection with the engine...")

            if retries_left > 0:
                # Reset the connection if there are attempts available
                # if context is in use (not 'null')
                if ext_conn_context is not None:
                    # reset connection and update context
                    (_, zmq_context, zmq_socket, engine_ip, engine_port) = reset_engine_connection(
                        ext_conn_context=ext_conn_context)
                    ext_conn_context.update_ext_conn_context(zmq_context=zmq_context,
                                                             zmq_socket=zmq_socket)
                else:
                    (_, zmq_context, zmq_socket, engine_ip, engine_port) = reset_engine_connection(
                        ext_conn_context, zmq_socket, engine_ip, engine_port, ext_conn_ID)

    # if context is in use and we have used all retries, or the reconnection success flag is not true
    if (retries_left == 0) and (ext_conn_context is not None):
        # then, mark the engine as disconnected
        ext_conn_context.engine_connected_flag = False

    return (delivered, reply, zmq_socket)


def disconnect_engine(ext_conn_context):
    '''
    function to close the connection with the engine
    '''
    logger.info("Disconnecting the external connector from the engine...")

    # inform the engine about the disconnection
    success, _, _ = send_info_to_engine(
        msg_type=MessageType.BYE, ext_conn_context=ext_conn_context)
    logger.info(f"Was the engine correctly informed about the disconnection? {success}. " +
                "Anyway, closing the connection with the engine...")
    # Wait before disconnect
    time.sleep(WAIT_BEFORE_DISCONNECT)
    ext_conn_context.zmq_socket.setsockopt(zmq.LINGER, 0)
    ext_conn_context.zmq_socket.close()
    ext_conn_context.zmq_context.term()

# ==========================================================================================
# Message Functions
# ==========================================================================================

# 'Enum' of different message types


class MessageType(Enum):
    HELLO = "HELLO"
    PING = "PING"
    PONG = "PONG"
    ORDER = "ORDER"
    ACK = "ACK"
    INFO = "INFO"
    BYE = "BYE"
    ERROR = "ERROR"
    BUSY = "BUSY"


# Constants of message fields
M_TYPE = "TYPE"
M_ID = "ID"
M_ENGINE_CODE = "ENGINE_CODE"
M_BODY = "BODY"
M_SECRET = "SECRET"
M_ENCRYPTED = "ENCRYPTED"
M_PUBKEY = "PUBKEY"
M_USE_SIGNATURE = "USE_SIGNATURE"

# Constants of secret "structure" to send the session key to the engine
S_KEY_FIELD = "session_key"
S_NONCE_FIELD = "nonce"

# Options of the field "USE_SIGNATURE"
M_USE_SIGNATURE_YES = "YES"
M_USE_SIGNATURE_NO = "NO"

# RSA labels
RSA_LABEL_SECRET = "secret"
RSA_LABEL_SESSION = "session"

# Other constants
MIN_WAITING_TIME_FOR_ENGINE_BUSY = 0.5
MAX_WAITING_TIME_FOR_ENGINE_BUSY = 1.0
EMPTY_MESSAGE_CONTENT = "None"

# ==========================================================================================
# Engine Comm encryption functions
# ==========================================================================================


def encrypt_using_rsa_key(rsa_key, string_to_encrypt, label):
    '''
    function to encrypt a string using a rsa public key
    https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#encryption
    '''

    # Encrypt the sting with the public RSA key
    b64_pub_key_comm = base64.b64decode(rsa_key)
    imported_pub_key = load_pem_public_key(b64_pub_key_comm)
    string_to_encrypt_bytes = bytes(string_to_encrypt.encode('utf-8'))

    encrypted_string = imported_pub_key.encrypt(
        string_to_encrypt_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=bytes(label, "utf-8")
        )
    )
    encrypted_string_hex = encrypted_string.hex()

    return encrypted_string_hex


def encrypt_session_key(rsa_key, session_key, nonce):
    '''
    function to encrypt the session key and the nonce using the public key received 
    from the engine for exchanging encrypted messages with the engine
    '''

    # Content to encrypt (encoded base64)
    secrets = {S_KEY_FIELD: session_key.hex(), S_NONCE_FIELD: nonce.hex()}

    # variables to return
    json_secrets_encrypted = ""
    success = False

    try:
        # serialize in json format map => string
        json_secrets = json.dumps(secrets)

        json_secrets_encrypted = encrypt_using_rsa_key(rsa_key,
                                                       json_secrets, RSA_LABEL_SESSION)

        success = True

    except TypeError as te:

        logger.error("exception serialising the session key and nonce in" +
                     "json format or formating the session key to be encrypted",
                     te, exc_info=True)

    return json_secrets_encrypted, success


def encrypt_content(content, session_cipher, nonce, engine_auth_code_sha512):
    '''
    This function encrypt content using the session cipher (Chacha20)
    https://cryptography.io/en/latest/hazmat/primitives/aead/
    '''
    bytes_chacha20_aad = bytes(engine_auth_code_sha512.encode('utf-8'))
    encrypted_content = session_cipher.encrypt(
        nonce,
        content.encode('utf-8'),
        bytes_chacha20_aad)

    return encrypted_content


def decrypt_content(raw_content_encrypted, session_cipher, nonce, engine_auth_code_sha512):
    '''
    Function to decrypt a message received from the engine
    https://cryptography.io/en/latest/hazmat/primitives/aead/ 
    '''
    byte_array_raw_content_encrypted = bytearray.fromhex(raw_content_encrypted)
    bytes_raw_content_encrypted = bytes(byte_array_raw_content_encrypted)
    bytes_chacha20_aad = bytes(engine_auth_code_sha512.encode('utf-8'))

    raw_content_decrypted = session_cipher.decrypt(
        nonce,
        bytes_raw_content_encrypted,
        bytes_chacha20_aad)

    return raw_content_decrypted

# ==========================================================================================
# Message processing functions
# ==========================================================================================


def message_packing(msg, session_cipher, is_HELLO_message, nonce, engine_auth_code_sha512):
    '''
    Function to serialize and encrypt the message (if needed)
    '''
    try:
        # serialize it in json format (msg -> string)
        json_msg = json.dumps(msg)

        # if session cipher is present and not 'null', and not a HELLO message;
        # then message should be encrypted
        if (session_cipher is not None) and (not is_HELLO_message):

            logging.debug("Message built, now encrypting the message " +
                          "to be sent to the engine")
            encrypted_message = encrypt_content(
                json_msg, session_cipher, nonce, engine_auth_code_sha512)
            msg_encrypted = {}
            msg_encrypted[M_ENCRYPTED] = encrypted_message.hex()

            # serialize it again in json format
            json_msg = json.dumps(msg_encrypted)
            logging.debug("Message encrypted and ready to be sent")

    except TypeError:
        json_msg = ""
        logger.exception(
            "Exception serialising a message in json format during message packing")

    return json_msg


def message_builder(msg_type, ext_conn_ID, ext_conn_secret, session_cipher=None,
                    info=None, rsa_key=None, nonce=None, engine_auth_code_sha512=None):
    '''
    This auxiliary function builds messages for the communication with the engine
    '''
    msg = {}
    msg[M_TYPE] = msg_type.value

    # instance ID
    msg[M_ID] = ext_conn_ID

    # flag for HELLO message type
    is_HELLO_message = (msg_type == MessageType.HELLO)

    # -----------------------------------------------------
    # MESSAGE BODY CONTENT
    # -----------------------------------------------------
    # Info not null or empty
    if (info is not None) and len(info) > 0:
        msg[M_BODY] = info

    else:
        msg[M_BODY] = EMPTY_MESSAGE_CONTENT

    # -----------------------------------------------------
    # ADDING THE SECRET (HASHED PASSWORD)
    # -----------------------------------------------------

    # HELLO message, encrypt the secret (password of the external connector)
    # using the RSA public key (if provided)
    if (session_cipher is not None) and is_HELLO_message and rsa_key is not None:

        msg[M_SECRET] = encrypt_using_rsa_key(
            rsa_key, ext_conn_secret, RSA_LABEL_SECRET)
        logging.debug(f"External connector secret: {ext_conn_secret}," +
                      " encrypted for sending the HELLO message")

    elif msg_type == MessageType.PING:
        msg[M_SECRET] = EMPTY_MESSAGE_CONTENT
        logging.debug("External connector secret not added: PING message")

    else:
        # for not PING OR HELLO messages, send the "secret" (hashed password) as it is
        msg[M_SECRET] = ext_conn_secret
        logging.debug(
            "External connector secret not encrypted for sending the message")

    json_msg = message_packing(msg, session_cipher, is_HELLO_message, nonce,
                               engine_auth_code_sha512)
    return json_msg


def message_reader(json_msg):
    '''
    This function gets a message received from the engine and
    produce a dictionay with the information
    '''
    try:
        # message processed
        msg_proc = json.loads(json_msg)

    except TypeError as te:
        msg_proc = {}
        logger.error(
            # in case of error, the variable 'msg_proc' is returned empty
            "exception processing a message from the engine", te, exc_info=True)

    return msg_proc


def check_engine_auth_code(engine_auth_code_blake2b, engine_auth_code_sha512,
                           use_signature, pub_key, engine_code_provided_by_engine):
    '''
    This function checks if the auth code provided by the the engine is correct or not,
    thec check is diferent in case we have to check the hash or the signature
    '''
    incorrect = False

    logger.info("Checking engine credentials...")

    if use_signature == M_USE_SIGNATURE_YES:

        if len(pub_key) > 0:
            logger.info("Checking the signature provided by the engine...")
            pub_key_bytes = base64.b64decode(pub_key)

            logger.debug(f"Public RSA key in use b64: {pub_key_bytes}")
            imported_pub_key = load_pem_public_key(pub_key_bytes)
            logger.info("Public RSA key imported!")

            try:
                # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#verification
                logger.debug(f"Expected hash hex: {engine_auth_code_sha512}")
                expected_hash = bytes.fromhex(engine_auth_code_sha512)

                singature_received = base64.b64decode(
                    engine_code_provided_by_engine)
                logger.debug(
                    f"Signature received b64: {engine_code_provided_by_engine}")

                # verify signature
                imported_pub_key.verify(
                    singature_received,
                    expected_hash,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA512()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    utils.Prehashed(hashes.SHA512())
                )
            except InvalidSignature as err:
                incorrect = True
                logger.warning("Engine signature not match!")

            except (AttributeError, ValueError) as err:
                incorrect = True
                logger.error(
                    "Error verifying the the signature of the engine", err)
        else:
            incorrect = True
            logger.error(
                "Engine public key is empty at the time of checking the engine signature!")
    else:
        logger.info("Checking the hash provided by the engine...")
        incorrect = not (engine_auth_code_blake2b ==
                         engine_code_provided_by_engine)

    if incorrect:
        logger.warning("The engine code is does not match. " +
                       f"Are we using cryptographic signature? {use_signature}")

    return incorrect


def message_processor(raw_reply, session_cipher, engine_auth_code_blake2b,
                      engine_auth_code_sha512, nonce):
    '''
    This function processes the response received form the engine and 
    provides the message processed, as well as some indicators to inform 
    about potential error or busy states from the engine (it also decrypt 
    the message if encrypted)
    '''
    # Flags to return
    error_flag = False
    busy_flag = False

    # Deserialize the message
    processed_reply = message_reader(raw_reply)

    if len(processed_reply) > 0:
        logger.debug("Message deserialized correctly")

        # if message is encrypted ('ENCRYPTED' field present)
        if M_ENCRYPTED in processed_reply:

            # decrypt the content and call again this function to process the raw content
            processed_reply_raw_content_decrypted = decrypt_content(
                processed_reply[M_ENCRYPTED], session_cipher, nonce,
                engine_auth_code_sha512)

            processed_reply, error_flag, busy_flag = message_processor(
                processed_reply_raw_content_decrypted, session_cipher,
                engine_auth_code_blake2b, engine_auth_code_sha512, nonce)

        # message not encrypted, or already decrypted
        else:
            # check engine auth code
            error_flag = check_engine_auth_code(engine_auth_code_blake2b, engine_auth_code_sha512,
                                                processed_reply[M_USE_SIGNATURE], processed_reply[M_PUBKEY],
                                                processed_reply[M_ENGINE_CODE])
            if error_flag:
                logger.warning(
                    f"Engine authorization code (hash or signature) not match")

            if (processed_reply[M_TYPE] == MessageType.ERROR.value):
                error_flag |= True
                logger.error(
                    f"Error message received from the engine: {processed_reply[M_BODY]}")

            elif (processed_reply[M_TYPE] == MessageType.BUSY.value):
                busy_flag |= True
                logger.warning(
                    f"Busy message received from the engine: {processed_reply[M_BODY]}")

            else:
                logger.info("Engine credentials are ok!")

    else:
        error_flag = True

    return processed_reply, error_flag, busy_flag

# ==========================================================================================
# Engine Interaction Functions
# ==========================================================================================


def send_info_to_engine(msg_type, info=None, ext_conn_context=None, v_zmq_socket=None,
                        v_engine_ip=None, v_engine_port=None, v_engine_time_out=None,
                        v_ext_conn_ID=None, v_ext_conn_secret=None, busy_retries=1,
                        v_session_cipher=None, v_engine_auth_code_blake2b=None,
                        v_engine_auth_code_sha_512=None, v_rsa_key=None, v_nonce=None):
    '''
    Function to send a message to engine. It uses either the context object, or the values ('v_') it needs directly. 
    If context is passed, then variables are not used
    '''
    # create a local variables that refers to the corresponding values used in the function
    if ext_conn_context is not None:
        local_zmq_socket = ext_conn_context.zmq_socket
        local_engine_time_out = ext_conn_context.engine_time_out
        local_ext_conn_ID = ext_conn_context.ext_conn_ID
        local_ext_conn_secret = ext_conn_context.ext_conn_secret
        local_engine_ip = ext_conn_context.engine_ip
        local_engine_port = ext_conn_context.engine_port
        local_session_cipher = ext_conn_context.cipher
        local_engine_auth_code_blake2b = ext_conn_context.engine_auth_code_blake2b
        local_engine_auth_code_sha512 = ext_conn_context.engine_auth_code_sha_512
        local_rsa_key = None
        local_nonce = ext_conn_context.nonce

    else:
        local_zmq_socket = v_zmq_socket
        local_engine_time_out = v_engine_time_out
        local_ext_conn_ID = v_ext_conn_ID
        local_ext_conn_secret = v_ext_conn_secret
        local_engine_ip = v_engine_ip
        local_engine_port = v_engine_port
        local_session_cipher = v_session_cipher
        local_engine_auth_code_blake2b = v_engine_auth_code_blake2b
        local_engine_auth_code_sha512 = v_engine_auth_code_sha_512
        local_rsa_key = v_rsa_key
        local_nonce = v_nonce

    # prepare message to send
    msg = message_builder(
        msg_type=msg_type,
        ext_conn_ID=local_ext_conn_ID,
        ext_conn_secret=local_ext_conn_secret,
        info=info,
        session_cipher=local_session_cipher,
        rsa_key=local_rsa_key,
        nonce=local_nonce,
        engine_auth_code_sha512=local_engine_auth_code_sha512)

    # try to send the message
    (success, reply, zmq_socket) = zeromq_message_delivery(
        msg,
        local_zmq_socket,
        local_engine_ip,
        local_engine_port,
        local_engine_time_out,
        local_ext_conn_ID,
        ext_conn_context)
    # initialization of the dictionary to receive the message from the engine
    processed_reply = {}

    if success:
        # processing of answer
        processed_reply, error_flag, busy_flag = message_processor(
            reply,
            local_session_cipher,
            local_engine_auth_code_blake2b,
            local_engine_auth_code_sha512,
            local_nonce)
        # is there any error sending the information?
        if error_flag:
            success = False
            logger.error("Error in the recepcion and processing of the message" +
                         f" from the engine. Message received: {processed_reply}")

        # is the engine busy?
        elif busy_flag:
            if(busy_retries <= 3):
                # wait a random time of seconds
                wait_time = random.uniform(MIN_WAITING_TIME_FOR_ENGINE_BUSY,
                                           MAX_WAITING_TIME_FOR_ENGINE_BUSY)
                logger.info(
                    "Message received from the engine, but it is busy. +"
                    f"Waiting some time ({wait_time} s) to try to resend the ping message. " +
                    f"Attempt number: {busy_retries}")
                time.sleep(wait_time)

                # retry
                busy_retries += 1  # update counter of attempts
                success, processed_reply, zmq_socket = send_info_to_engine(
                    msg_type,
                    info,
                    ext_conn_context,
                    v_zmq_socket,
                    v_engine_ip,
                    v_engine_port,
                    v_engine_time_out,
                    v_ext_conn_ID,
                    v_ext_conn_secret,
                    busy_retries)
            else:
                success = False
                logger.warning(
                    "Engine is always busy, message delivery has failed")
        else:
            logger.info("Message successfully delivered")

    else:
        logger.warning("Engine does not answer, message delivery has failed")

    return success, processed_reply, zmq_socket


def ping_engine(zmq_socket, ext_conn_ID, ext_conn_secret, engine_time_out, engine_ip,
                engine_port, engine_auth_code_blake2b, engine_auth_code_sha_512, busy_retries=1):
    '''
    Function to test if a connection with the engine is working, and get the material 
    to establish an encrypted connection (message level)
    '''
    success, processed_reply, zmq_socket = send_info_to_engine(
        msg_type=MessageType.PING,
        info=None,
        ext_conn_context=None,
        v_zmq_socket=zmq_socket,
        v_engine_ip=engine_ip,
        v_engine_port=engine_port,
        v_engine_time_out=engine_time_out,
        v_ext_conn_ID=ext_conn_ID,
        v_ext_conn_secret=ext_conn_secret,
        v_engine_auth_code_blake2b=engine_auth_code_blake2b,
        v_engine_auth_code_sha_512=engine_auth_code_sha_512)

    if success:
        if (processed_reply[M_TYPE] == MessageType.PONG.value):
            logger.info(
                f"PONG message received from engine:{processed_reply[M_ID]}, " +
                "connection with the engine working as expected")

        else:
            success &= False
            logger.warning("Engine message has sent a messgae, but it is not the 'PONG' message expected. " +
                           f"Type received: {processed_reply[M_TYPE]}")
    else:
        logger.error("The connection with engine is not working")

    if M_BODY in processed_reply:
        msg_body = processed_reply[M_BODY]
    else:
        msg_body = None

    return success, msg_body, zmq_socket


def wait_for_engine_message(ext_conn_context):
    '''
    Method to wait for engine messages (to be used within the oversee loop). 
    The waiting time will be the greater value between the engine connection 
    time out and the operation checking time
    '''
    time_to_wait = max(ext_conn_context.engine_time_out,
                       ext_conn_context.check_time_operation_loop)
    msg_received, reply = receive_messages_from_engine(
        ext_conn_context.zmq_socket, time_to_wait)

    # message received?
    if msg_received:
        processed_reply, _, _ = message_processor(
            reply,
            ext_conn_context.cipher,
            ext_conn_context.engine_auth_code_blake2b,
            ext_conn_context.engine_auth_code_sha_512,
            ext_conn_context.nonce)
    else:
        processed_reply = {}

    return msg_received, processed_reply
