"""
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega external connector
=================================================
Module: connection_utils.py
Author: Alberto Dominguez 

This module contains elements to help the management of the connection and the register
"""

import logging
import random
import secrets
import tempfile

from cryptography.hazmat.primitives import serialization

import utils.interoperability_py_go as interpygo


# logger
logger = logging.getLogger(__name__)

NUMBER_CHAR_CLIENT_SOCKET_ID = 5

# ==========================================================================================
# AUXILIARY FUNCTIONS & STUFF
# ==========================================================================================

# ----------------------------
#   CLIENT SOCKETS ID
# ----------------------------


def get_client_socket_id_list(number_of_connections):
    # Get client sockets IDs
    socket_id_list = set()
    for _ in range(0, number_of_connections):
        socket_id_list.add(select_characters_from_dict(
            ALPHANUMERIC_DICT, NUMBER_CHAR_CLIENT_SOCKET_ID))
    return socket_id_list


# ----------------------------
#   TLS PRIVATE KEY LOADING
# ----------------------------


def load_protected_private_key(tls_priv_key_pem_file, tls_key_password):
    '''
    Function to load the private key for DTLS/TLS connections by creating
    a temporary file for the file
    '''
    error = False
    with open(tls_priv_key_pem_file) as privatefile:
        tls_priv_key_pem_file_content = privatefile.read()
    try:
        tls_priv_key_pem_object = serialization.load_pem_private_key(
            tls_priv_key_pem_file_content.encode(), tls_key_password.encode())

        tls_priv_key_pem_content = tls_priv_key_pem_object.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())

        # Create temporary file to save the key to be used for the DTLS library
        _, tls_priv_key_pem = tempfile.mkstemp()
        with open(tls_priv_key_pem, 'w') as f:
            f.write(tls_priv_key_pem_content.decode('UTF-8'))
    except:
        error = True
        logger.exception(
            "Error creating a temporary file for the private protected key")

    return tls_priv_key_pem, error


def prepare_redis_client_key_file(redis_priv_key_protected, redis_priv_key_password,
                                  redis_priv_key_client):
    '''
    Auxiliary function to process the key file needed for redis when it is protected
    '''
    redis_key_file = None
    error = False
    if redis_priv_key_protected:
        redis_key_file, error = load_protected_private_key(
            redis_priv_key_client, redis_priv_key_password)
    else:
        redis_key_file = redis_priv_key_client
    return redis_key_file, error


# ----------------------------
#   SESSION
# ----------------------------
# session id autogenerated default length
DEFAULT_LENGHT = 12

# session id autogenerated options
NUMBERS = "numbers"
HEX_LOWER = "hex_lower"
HEX_UPPER = "hex_upper"
HEX_MIX = "hex_mix"
ALPHANUMERIC_UPPER = "alphanumeric_upper"
ALPHANUMERIC_LOWER = "alphanumeric_lower"
ALPHANUMERIC_AND_SYMBOLS_UPPER = "alphanumeric_and_symbols_upper"
ALPHANUMERIC_AND_SYMBOLS_LOWER = "alphanumeric_and_symbols_upper"
ALPHANUMERIC_MIX = "alphanumeric_mix"
ALPHANUMERIC_AND_SYMBOLS_MIX = "alphanumeric_and_symbols_mix"

# 'Dictionary' of characters to pick up randomly to create a session id
NUMBER_DICT = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
HEX_DICT = [*NUMBER_DICT, 'A', 'B', 'C', 'D', 'E', 'F']
ALPHANUMERIC_DICT = [*HEX_DICT, 'G', 'H', 'I', 'J', 'K', 'L', 'M',
                     'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
ALPHANUMERIC_AND_SYMBOLS_DICT = [*ALPHANUMERIC_DICT, '/', '?', '+', '-', '*', '=', ':', '[', ']',
                                 '^', '@', '#', '$', '%', '&', '(', ')', '_', '!', '<', '>', '|']


def select_characters_from_dict(dictionary_of_chars, number_of_chars):
    '''
    Function to select a set of chars given a dictionary
    '''
    session_id = "".join(secrets.choice(dictionary_of_chars)
                         for _ in range(number_of_chars))
    return session_id


def mix_upper_lower_letters(session_id_candidate):
    '''
    Method to mix lower and upper letters given a session id candidate
    https://stackoverflow.com/questions/45547549/randomizing-the-upper-and-lowercase-of-a-string
    '''
    session_id_list = list()
    char_catalogue_list = [
        session_id_candidate.upper(), session_id_candidate.lower()]
    index = 0

    for _ in session_id_candidate:
        char_catalogue_picked = random.SystemRandom().choice(char_catalogue_list)
        session_id_list.append(char_catalogue_picked[index])
        index += 1
    session_id = ''.join(session_id_list)

    return session_id


def get_autogenerated_token(type_of_chars, number_of_chars):
    '''
    Function to get a autogenerated session id
    '''
    if number_of_chars and not (isinstance(number_of_chars, int) and number_of_chars > 0):
        number_of_chars = DEFAULT_LENGHT
        logger.info(
            "Default number of number of characters for sessionID in use")

    type_of_chars = type_of_chars.lower()

    # characters type selector
    if type_of_chars == NUMBERS:
        token = select_characters_from_dict(NUMBER_DICT, number_of_chars)
    elif type_of_chars == HEX_LOWER:
        token = select_characters_from_dict(
            HEX_DICT, number_of_chars).lower()
    elif type_of_chars == HEX_UPPER:
        token = select_characters_from_dict(
            HEX_DICT, number_of_chars).upper()
    elif type_of_chars == HEX_MIX:
        token = mix_upper_lower_letters(
            select_characters_from_dict(HEX_DICT, number_of_chars))
    elif type_of_chars == ALPHANUMERIC_UPPER:
        token = select_characters_from_dict(
            ALPHANUMERIC_DICT, number_of_chars).upper()
    elif type_of_chars == ALPHANUMERIC_LOWER:
        token = select_characters_from_dict(
            ALPHANUMERIC_DICT, number_of_chars).lower()
    elif type_of_chars == ALPHANUMERIC_MIX:
        token = mix_upper_lower_letters(
            select_characters_from_dict(ALPHANUMERIC_DICT, number_of_chars))
    elif type_of_chars == ALPHANUMERIC_AND_SYMBOLS_UPPER:
        token = select_characters_from_dict(
            ALPHANUMERIC_AND_SYMBOLS_DICT, number_of_chars).upper()
    elif type_of_chars == ALPHANUMERIC_AND_SYMBOLS_LOWER:
        token = select_characters_from_dict(
            ALPHANUMERIC_AND_SYMBOLS_DICT, number_of_chars).lower()
    elif type_of_chars == ALPHANUMERIC_AND_SYMBOLS_MIX:
        token = mix_upper_lower_letters(select_characters_from_dict(
            ALPHANUMERIC_AND_SYMBOLS_DICT, number_of_chars))
    else:
        token = select_characters_from_dict(
            ALPHANUMERIC_DICT, number_of_chars).lower()
    return token


# ----------------------------
#   MEMORY VARIABLES
# ----------------------------
NUMBER_DIGITS_RANDOM_FLOAT = 2


def aux_conv_rules_memory_init(mem_variables, id_conn):
    '''
    Function to initialise the memory variables provided in the conversation rules
    '''
    memory = dict()
    for element in mem_variables:
        if interpygo.interlanguage_bool_check(element.AutoGeneration.Enable):
            # Autogeneration of number value (float)
            if element.Type.lower() == interpygo.FLOAT:
                min_limit = interpygo.get_pythonic_value(
                    interpygo.get_python_type(element.Type),
                    element.AutoGeneration.MinLimitInterval)
                max_limit = interpygo.get_pythonic_value(
                    interpygo.get_python_type(element.Type),
                    element.AutoGeneration.MaxLimitInterval)
                memory[element.Name] = round(random.SystemRandom().uniform(min_limit, max_limit),
                                             NUMBER_DIGITS_RANDOM_FLOAT)

            # Autogeneration of number value (int)
            elif element.Type.lower() == interpygo.INT:
                min_limit = interpygo.get_pythonic_value(
                    interpygo.get_python_type(element.Type),
                    element.AutoGeneration.MinLimitInterval)
                max_limit = interpygo.get_pythonic_value(
                    interpygo.get_python_type(element.Type),
                    element.AutoGeneration.MaxLimitInterval)
                memory[element.Name] = random.SystemRandom().randint(
                    min_limit, max_limit)

            # Autogeneration of bool
            elif element.Type.lower() == interpygo.BOOL:
                memory[element.Name] = bool(
                    random.SystemRandom().getrandbits(1))

            # Autogeneration of String value
            else:
                memory[element.Name] = interpygo.get_pythonic_value(
                    interpygo.get_python_type(element.Type),
                    get_autogenerated_token(element.AutoGeneration.CharactersType,
                                            element.AutoGeneration.NumberCharacters))
        else:
            # if default value is provided
            if len(element.DefaultValue) > 0:
                memory[element.Name] = interpygo.get_pythonic_value(
                    interpygo.get_python_type(element.Type),
                    element.DefaultValue)
            # if not
            else:
                if element.Type.lower() == interpygo.FLOAT:
                    memory[element.Name] = 0.00
                elif element.Type.lower() == interpygo.INT:
                    memory[element.Name] = 0
                elif element.Type.lower() == interpygo.BOOL:
                    memory[element.Name] = False
                else:
                    memory[element.Name] = ""

        if id_conn == 0:
            logger.info(f"Added a new memory element for global variables " +
                        f"Name:'{element.Name}', value:'{memory[element.Name]}', type:{type(memory[element.Name])}")
        elif id_conn > 0:
            logger.info(f"Added a new memory element for the connection:{id_conn}. " +
                        f"Name:'{element.Name}', value:'{memory[element.Name]}', type:{type(memory[element.Name])}")
        else:
            logger.info(f"Prepared a new memory element for the multi external connector variables " +
                        f"Name:'{element.Name}', value:'{memory[element.Name]}', type:{type(memory[element.Name])}")
    return memory


def get_mem_var_names_to_report(conv_rules_mem_variables):
    '''
    Auxiliary function to get the list of memory variables that should be reported
    at the time of reporting memory
    '''
    reporting_list = dict()
    # Remove file importing information 
    conv_rules_mem_variables.Import = None
    
    for _, mem_var_set in conv_rules_mem_variables.__dict__.items():
        if mem_var_set  is not None:
            for element in mem_var_set:
                reporting_list[element.Name] = interpygo.interlanguage_bool_check(
                    element.ToBeReported)

    return reporting_list


# ----------------------------
#   ENCODING
# ----------------------------
# Encoding types
UTF_8 = "utf-8"
UTF_16 = "utf-16"
UTF_32 = "utf-32"
ASCII = "ascii-8"

# switcher encoding
switcher_encoding = {
    UTF_8: "utf-8",
    UTF_16: "utf-16",
    UTF_32: "utf-32",
    ASCII: "ascii-8"
}
