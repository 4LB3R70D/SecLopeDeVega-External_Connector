"""
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega external connector
=================================================
Module: conversation_module.py
Author: Alberto Dominguez

This is module contains the business logic of the conversation with external agents.
It receives the conversation rules from the engine during starting phase and used them
for external inputs
"""
import base64
import concurrent.futures
import hashlib
import importlib
import json
import logging
import re
import sys
from inspect import getmembers, isfunction
from types import SimpleNamespace
from typing import Tuple

import ext_conn_comms.engine_comm_service as eng_com
from ext_conn_comms.engine_comm_service import M_BODY
from utils.interoperability_py_go import (get_pythonic_value,
                                          interlanguage_bool_check)
from utils.memory_operations import (compare_two_memory_variables_values,
                                     do_memory_operation)

# logger
logger = logging.getLogger(__name__)

# constants rules
SYNC_MODE = "sync"
ASYNC_MODE = "async"
HYBRID_MODE = "hybrid"

# fixed session response parameters
SESSION_KEY_PARAMETER = "SESSION_KEY"
SESSION_VALUE_PARAMETER = "SESSION_VALUE"
IP_VALUE_PARAMETER = "IP"
PORT_VALUE_PARAMETER = "PORT"

# Capturing struct
RULE_ID = "RULE_ID"
CAPTURES = "CAPTURES"

# Others
ONE_RESULT_OF_CUSTOM_FUNCTION = 1

# Custom functions especial parameters
CUSTOM_FUNCTION_EXTERNAL_INPUT = "EXT_IN"
CUSTOM_FUNCTION_PROCESSORS_INPUT_OUTPUT = "PROCESSOR_INPUT_OUTPUT"


# Memory operation
STRING_OPERATION = "STR"
NUMBER_OPERATION = "NBR"
BOOL_OPERATION = "LGC"

# ==========================================================================================
# Initialisation Functions
# =========================================================================================


def optimize_rule(rule):
    '''
    Function to optimize a specific rule (regex)
    '''
    # if rule is not asynchronous, compile the regex and decodebase64
    if rule.Mode != ASYNC_MODE:
        if interlanguage_bool_check(rule.RegexBase64Flag):
            rule.Regex = re.compile(
                base64.b64decode(rule.Regex).decode("utf-8"))
            rule.RegexBase64Flag = False
        else:
            rule.Regex = re.compile(rule.Regex)

        if interlanguage_bool_check(rule.ResponseBase64Flag):
            rule.Response = base64.b64decode(rule.Response).decode("utf-8")
            rule.ResponseBase64Flag = False

        # For each capture group (if not null/None)
        if rule.Capturing.Captures is not None:
            for capture in rule.Capturing.Captures:
                # Capture regex in b64?
                if interlanguage_bool_check(capture.B64Flag):
                    capture.Regex = re.compile(
                        base64.b64decode(capture.Regex).decode("utf-8"))
                    capture.B64Flag = False
                else:
                    capture.Regex = re.compile(capture.Regex)
    return rule


def optimization_conversation_rules(cnv_rules):
    '''
    Function to compile the regular expressions before being used to optimize the execution,
    and decode base64 information if present
    '''
    for rule in cnv_rules.Conversation.CustomRules.Rules:
        rule = optimize_rule(rule)

    if cnv_rules.Conversation.CustomRules.Groups is not None:
        for group in cnv_rules.Conversation.CustomRules.Groups:
            # 'optimize' the regex of the group
            if interlanguage_bool_check(group.RegexBase64Flag):
                group.Regex = re.compile(
                    base64.b64decode(group.Regex).decode("utf-8"))
                group.RegexBase64Flag = False
            else:
                group.Regex = re.compile(group.Regex)

            # 'optimize' the rules
            for rule in group.Rules:
                rule = optimize_rule(rule)

    # Add the names to the basic conversation rules for informing when they are executed in the logs
    cnv_rules.Conversation.Greetings.Name = "GREETINGS"
    cnv_rules.Conversation.Default.Name = "DEFAULT"
    cnv_rules.Conversation.Empty.Name = "EMPTY"
    cnv_rules.Conversation.Timeout.Name = "TIMEOUT"
    cnv_rules.Conversation.Ending.Name = "ENDING"

    # Decode b64 basic rules inforamtion if present
    if interlanguage_bool_check(cnv_rules.Conversation.Greetings.B64Flag):
        cnv_rules.Conversation.Greetings.Value = base64.b64decode(
            cnv_rules.Conversation.Greetings.Value).decode("utf-8")
        cnv_rules.Conversation.Greetings.B64Flag = False

    if interlanguage_bool_check(cnv_rules.Conversation.Default.B64Flag):
        cnv_rules.Conversation.Default.Value = base64.b64decode(
            cnv_rules.Conversation.Default.Value).decode("utf-8")
        cnv_rules.Conversation.Default.B64Flag = False

    if interlanguage_bool_check(cnv_rules.Conversation.Empty.B64Flag):
        cnv_rules.Conversation.Empty.Value = base64.b64decode(
            cnv_rules.Conversation.Empty.Value).decode("utf-8")
        cnv_rules.Conversation.Empty.B64Flag = False

    if interlanguage_bool_check(cnv_rules.Conversation.Timeout.B64Flag):
        cnv_rules.Conversation.Timeout.Value = base64.b64decode(
            cnv_rules.Conversation.Timeout.Value).decode("utf-8")
        cnv_rules.Conversation.Timeout.B64Flag = False

    if interlanguage_bool_check(cnv_rules.Conversation.Ending.B64Flag):
        cnv_rules.Conversation.Ending.Value = base64.b64decode(
            cnv_rules.Conversation.Ending.Value).decode("utf-8")
        cnv_rules.Conversation.Ending.B64Flag = False

    return cnv_rules


def load_conversation_rules(msg_proc):
    '''
    This function process the first message received and load the conversation rules for the session.
    '''
    success = False
    cnv_rules = None
    hash_conversation_rules_used = None

    # check if the result of the message processing is not empty
    if msg_proc and len(msg_proc) > 0 and M_BODY in msg_proc and len(msg_proc[M_BODY]) > 0:
        # Conversation Rules Object (shared among threads)
        # https://stackoverflow.com/questions/6578986/how-to-convert-json-data-into-a-python-object

        cnv_rules = json.loads(
            msg_proc[M_BODY], object_hook=lambda d: SimpleNamespace(**d))
        cnv_rules = optimization_conversation_rules(cnv_rules)
        # get a hash of the conversation rules used during this execution for future validation about
        # what conversation rules have been used
        m = hashlib.sha512()
        m.update(msg_proc[M_BODY].encode("UTF-8"))
        hash_conversation_rules_used = m.hexdigest()
        success = True
    else:
        logger.warning(
            "Empty or incomplete message after processing the raw message received from the engine")

    return (success, cnv_rules, hash_conversation_rules_used)


def get_conversation_rules(success, ext_conn_ID, ext_conn_secret, zmq_socket, engine_time_out, engine_ip,
                           engine_port, engine_encryption, rsa_key, session_key, session_cipher, nonce,
                           engine_auth_code_blake2b, engine_auth_code_sha_512):
    '''
    This function is the main component to initilise the conversation rules via contacting the engine and
    get the conversation rules and do the logical connection with the engine
    '''
    # encrypt session key and nonce with the pub key received if applicable, and then, add it in the msg body
    if engine_encryption:
        msg_body, success = eng_com.encrypt_session_key(
            rsa_key, session_key, nonce)
    else:
        # if encryption is not in use, nothing to add in the message body
        msg_body = eng_com.EMPTY_MESSAGE_CONTENT

    if success:
        # prepare message for contacting the engine and get the conversation rules
        success_onboarding, processed_reply, zmq_socket = eng_com.send_info_to_engine(
            msg_type=eng_com.MessageType.HELLO,
            info=msg_body,
            ext_conn_context=None,
            v_zmq_socket=zmq_socket,
            v_engine_ip=engine_ip,
            v_engine_port=engine_port,
            v_engine_time_out=engine_time_out,
            v_ext_conn_ID=ext_conn_ID,
            v_ext_conn_secret=ext_conn_secret,
            v_rsa_key=rsa_key,
            v_session_cipher=session_cipher,
            v_nonce=nonce,
            v_engine_auth_code_blake2b=engine_auth_code_blake2b,
            v_engine_auth_code_sha_512=engine_auth_code_sha_512)

        if success_onboarding and (
                processed_reply[eng_com.M_TYPE] == eng_com.MessageType.HELLO.value):
            success_load_cnv_rules, cnv_rules, hash_conversation_rules_used = load_conversation_rules(
                processed_reply)
            success &= success_load_cnv_rules
        else:
            success = False
            cnv_rules = None
            logger.warning(
                "The onboarding of the external connector was not possible, the execution will stop")
    else:
        success = False
        cnv_rules = None
        logger.warning(
            "Encrypting the session key was not possible, the execution will stop")

    return (success, cnv_rules, zmq_socket, hash_conversation_rules_used)

# ==========================================================================================
# Operation functions for memory operations
# =========================================================================================


def check_one_memory_and_conditions(memory, conditions, other_memory_1=None, other_memory_2=None):
    '''
    Auxiliary function to check if some conditions are met in the current memory. 
    In case of comparing one memory variable with another, the other memories should 
    be provided just in case the reference variable is present in one of these memories,
    instead of the one where the memory variable to check is present
    '''
    mem_ok = True
    present = False

    # 'null' check
    if conditions is not None and memory is not None:
        # For each memory condition of the rule
        for condition in conditions:

            # Checking if the memory variable has the right fixed value
            if condition.VarName in memory:
                present = True
                expected_value = None

                # Checking if the memory variable has the same value of the reference variable
                if condition.ReferenceVariable is not None and len(condition.ReferenceVariable) > 0:
                    reference_memory = None

                    if condition.ReferenceVariable in memory:
                        reference_memory = memory
                    elif other_memory_1 is not None and condition.ReferenceVariable in other_memory_1:
                        reference_memory = other_memory_1
                    elif other_memory_2 is not None and condition.ReferenceVariable in other_memory_2:
                        reference_memory = other_memory_2

                    if reference_memory is not None:
                        expected_value = reference_memory[condition.ReferenceVariable]
                        mem_ok &= compare_two_memory_variables_values(
                            memory[condition.VarName],
                            expected_value)

                # Checking if the memory variable has the right fixed value
                else:
                    if condition.Value is not None:
                        # Get the condition value as a ptyhon variable, instead of string
                        expected_value = get_pythonic_value(
                            type(memory[condition.VarName]), condition.Value)
                        # Do comparison
                        mem_ok &= memory[condition.VarName] == expected_value

                if mem_ok:
                    logger.debug(
                        f"The memory value '{condition.VarName}' has the value needed")
                else:
                    logger.debug(f"The memory value '{condition.VarName}' has NOT the value needed. " +
                                 f"Current value: '{memory[condition.VarName]}', value needed: '{expected_value}'")
            else:
                mem_ok &= False
                logger.debug(
                    f"The memory condition '{condition.VarName}' needed is not detected in this memory")
    return mem_ok, present


def check_memory_and_rule(rule, memory, other_memory_1, other_memory_2):
    '''
    Function to check if a given rule satisfies the memory conditions that allow its execution
    '''
    logger.debug(
        f"Checking the conditions needed by the rule: {rule.Id}")
    mem_ok = check_memory_conditions(
        rule.Memory.Conditions,  memory,  other_memory_1, other_memory_2)

    return mem_ok


def get_value_from_a_reference_variable(memory_reference_variable, multi_ext_conn_mem, global_mem, conn_mem):
    '''
    Auxiliary function to get the value from a reference value to be loaded to another memory variable
    '''
    value_reference_variable = None

    if memory_reference_variable in multi_ext_conn_mem:
        value_reference_variable = multi_ext_conn_mem[memory_reference_variable]

    elif memory_reference_variable in global_mem:
        value_reference_variable = global_mem[memory_reference_variable]

    elif memory_reference_variable in conn_mem:
        value_reference_variable = conn_mem[memory_reference_variable]

    else:
        logger.warning(
            f"Reference variable '{memory_reference_variable}' not found in the memories!")

    return value_reference_variable


def add_memory_variable_into_the_modification_list(update_using_fixed_value, modification_list,
                                                   memory_variable_name, memory_variable_raw_value,
                                                   memory_that_contains_the_variable, memory_reference_variable,
                                                   multi_ext_conn_mem, global_mem, conn_mem):
    '''
    Auxiliary function to add a memory variable to be modified into the corresponding modification list
    '''
    # Update a memory variable using a fixed value
    if update_using_fixed_value:
        modification_list[memory_variable_name] = get_pythonic_value(
            type(memory_that_contains_the_variable[memory_variable_name]),
            memory_variable_raw_value)
    # Update a memory variable using another memory variable
    else:
        value_reference_variable = get_value_from_a_reference_variable(
            memory_reference_variable, multi_ext_conn_mem, global_mem, conn_mem)
        if value_reference_variable is not None:
            modification_list[memory_variable_name] = value_reference_variable

    return modification_list


def prepare_mem_variable_to_be_modified(memory_variable_name, memory_variable_raw_value,
                                        memory_reference_variable,
                                        modification_list_multi, modification_list_global,
                                        modification_list_conn, multi_ext_conn_mem,
                                        global_mem, conn_mem):
    '''
    Function to prepare a memory variable to be modified, and add it in
    the correspoind list (python dict) to be processed later on
    '''
    update_using_fixed_value = True

    if memory_reference_variable is not None and len(memory_reference_variable) > 0:
        update_using_fixed_value = False

    if memory_variable_name in conn_mem:
        modification_list_conn = add_memory_variable_into_the_modification_list(
            update_using_fixed_value, modification_list_conn,
            memory_variable_name, memory_variable_raw_value,
            conn_mem, memory_reference_variable,
            multi_ext_conn_mem, global_mem, conn_mem)

        logger.debug(
            f"The memory variable '{memory_variable_name}' found to be updated found in the connection memory")

    elif memory_variable_name in global_mem:
        modification_list_global = add_memory_variable_into_the_modification_list(
            update_using_fixed_value, modification_list_global,
            memory_variable_name, memory_variable_raw_value,
            global_mem, memory_reference_variable,
            multi_ext_conn_mem, global_mem, conn_mem)

        logger.debug(
            f"The memory variable '{memory_variable_name}' found to be updated found in the global memory")

    elif memory_variable_name in multi_ext_conn_mem:
        modification_list_multi = add_memory_variable_into_the_modification_list(
            update_using_fixed_value, modification_list_multi,
            memory_variable_name, memory_variable_raw_value,
            multi_ext_conn_mem, memory_reference_variable,
            multi_ext_conn_mem, global_mem, conn_mem)

        logger.debug(
            f"The memory variable '{memory_variable_name}' found to be updated found in the multi external " +
            "connector memory")

    elif memory_variable_name == CUSTOM_FUNCTION_PROCESSORS_INPUT_OUTPUT:
        # Nothing to do, this is a value used for managing the preprocessor and postprocessor custom functions
        pass
    else:
        logger.warning(
            f"The memory variable '{memory_variable_name}' to be updated were not found in memories")

    return modification_list_multi, modification_list_global, modification_list_conn


def get_potential_memory_mods_using_captured_data(captured_data, multi_ext_conn_mem, global_mem, conn_mem):
    '''
    Function to prepare the list of potential modifications according to the captured data from outside
    captured_data = set() => captured_data.add(rule_data_captured)
    rule_data_captured = {
        RULE_ID : rule.Id,
        CAPTURES: dict() => rule_data_captured[CAPTURES][capture.MemVarName] = incoming_data_captured
        }
    '''
    # list (python dict) of potential modifications of memory variables.
    # In case there are several modifications applicable to
    # the same memory variable, the last one is applied
    memory_mod_for_capturing_multi_ext_conn_mem = dict()
    memory_mod_for_capturing_global = dict()
    memory_mod_for_capturing_conn = dict()

    if captured_data is not None and len(captured_data) > 0:
        # For each data captured per rule
        for rule_capturing in captured_data:
            # for the different captures of the rule
            for memory_variable, capture in rule_capturing[CAPTURES].items():

                # add it in the modification list
                # memory_reference_variable = None
                # # (we are not using a memory variable as reference here)
                memory_mod_for_capturing_multi_ext_conn_mem, memory_mod_for_capturing_global,\
                    memory_mod_for_capturing_conn = prepare_mem_variable_to_be_modified(
                        memory_variable,
                        capture, None,
                        memory_mod_for_capturing_multi_ext_conn_mem,
                        memory_mod_for_capturing_global,
                        memory_mod_for_capturing_conn,
                        multi_ext_conn_mem, global_mem, conn_mem)
    else:
        logger.debug(
            "The 'captured_data' variable is empty at the time of getting potential memory mods")

    return (memory_mod_for_capturing_multi_ext_conn_mem, memory_mod_for_capturing_global,
            memory_mod_for_capturing_conn)


def get_potential_memory_mods_using_rules(conv_rules, multi_ext_conn_mem, global_mem, conn_mem):
    '''
    Function to prepare the list of potential modifications according to the conversation 
    rules memory updates
    '''
    # list (python dict) of potential modifications of memory variables.
    # In case there are several modifications applicable to
    # the same memory variable, the last one is applied
    memory_mod_for_rules_multi_ext_conn_mem = dict()
    memory_mod_for_rules_global = dict()
    memory_mod_for_rules_conn = dict()

    if conv_rules is not None and len(conv_rules) > 0:
        # For each data captured per rule
        for rule in conv_rules:
            if rule.Memory.Updates is not None:  # Null check
                for mem_element in rule.Memory.Updates:
                    (memory_mod_for_rules_multi_ext_conn_mem, memory_mod_for_rules_global,
                     memory_mod_for_rules_conn) =\
                        prepare_mem_variable_to_be_modified(
                            mem_element.VarName, mem_element.Value,
                            mem_element.ReferenceVariable,
                            memory_mod_for_rules_multi_ext_conn_mem,
                            memory_mod_for_rules_global,
                            memory_mod_for_rules_conn,
                            multi_ext_conn_mem, global_mem, conn_mem)
    else:
        logger.debug(
            "The 'conv_rules' variable is empty at the time of getting potential memory mods")

    return memory_mod_for_rules_multi_ext_conn_mem, memory_mod_for_rules_global,\
        memory_mod_for_rules_conn


def prepare_memory_operation_parameters(mem_ops, external_input_output,
                                        multi_ext_conn_mem, global_mem,
                                        conn_mem, ip, port, session_key, session_value):
    '''
    Function to prepare a list of parameters to be used for the custom function or 
    memory operation from the external input/output and the memory variables
    '''
    params = list()
    for input in mem_ops.Input:
        if (input.upper() == CUSTOM_FUNCTION_EXTERNAL_INPUT or
                input.upper() == CUSTOM_FUNCTION_PROCESSORS_INPUT_OUTPUT):
            params.append(external_input_output)
        elif input.upper() == IP_VALUE_PARAMETER:
            params.append(ip)
        elif input.upper() == PORT_VALUE_PARAMETER:
            params.append(port)
        elif input.upper() == SESSION_KEY_PARAMETER:
            params.append(session_key)
        elif input.upper() == SESSION_VALUE_PARAMETER:
            params.append(session_value)
        elif input in multi_ext_conn_mem:
            params.append(multi_ext_conn_mem[input])
        elif input in global_mem:
            params.append(global_mem[input])
        elif input in conn_mem:
            params.append(conn_mem[input])
        elif len(mem_ops.Operation) > 0:
            # Built-in memory operation
            if re.match(STRING_OPERATION, mem_ops.Operation):
                params.append(get_pythonic_value(str, input))
            elif re.match(NUMBER_OPERATION, mem_ops.Operation):
                params.append(get_pythonic_value(float, input))
            elif re.match(BOOL_OPERATION, mem_ops.Operation):
                params.append(get_pythonic_value(bool, input))
        else:
            params.append(input)

    return params


def process_memory_operation_results(mem_ops, results, multi_ext_conn_mem, global_mem, conn_mem):
    '''
    Function to process the results of the custom functions or built-in memory operations 
    and prepare them to be added in the corresponding memory variable
    '''
    memory_mod_for_functions_multi_ext_conn_mem = dict()
    memory_mod_for_functions_global = dict()
    memory_mod_for_functions_conn = dict()

    for idx, output in enumerate(mem_ops.Output):
        # Get the value
        if isinstance(results, Tuple) or isinstance(results, list):
            if idx < len(results):
                new_value = results[idx]
            else:
                logger.warning("Custom Function/Memory Operation is not providing enough results for " +
                               f"all required declared outputs. Memory variable:'{output}'" +
                               "will be filled using 'None'")
                new_value = None
        else:
            # Only one result is returned by the custom function
            new_value = results

        # Add it in the corresponding update list and esure the data type remains the same
        # reference variable not applicable in this case (that is why it is None)
        memory_mod_for_functions_multi_ext_conn_mem, memory_mod_for_functions_global, memory_mod_for_functions_conn =\
            prepare_mem_variable_to_be_modified(
                output, new_value, None,
                memory_mod_for_functions_multi_ext_conn_mem,
                memory_mod_for_functions_global,
                memory_mod_for_functions_conn,
                multi_ext_conn_mem,
                global_mem,
                conn_mem)

    return memory_mod_for_functions_multi_ext_conn_mem, memory_mod_for_functions_global, memory_mod_for_functions_conn


def check_and_import_the_custom_functions_module(custom_functions_name):
    '''
    Function to check if the custom functions module is imported, and if not, do it
    '''
    slv_custom_functions_mod = None

    if not custom_functions_name in sys.modules:
        # https://stackoverflow.com/questions/14050281/how-to-check-if-a-python-module-exists-without-importing-it
        custom_function_module_exists = importlib.util.find_spec(
            custom_functions_name) is not None
        if custom_function_module_exists:
            slv_custom_functions_mod = importlib.import_module(
                custom_functions_name)
            sys.modules[custom_functions_name] = slv_custom_functions_mod
    else:
        slv_custom_functions_mod = sys.modules[custom_functions_name]

    return slv_custom_functions_mod


def find_custom_function(custom_function_name, slv_custom_functions_mod):
    '''
    Function to find a find a custom function
    '''
    found_function = False
    # https://stackoverflow.com/questions/139180/how-to-list-all-functions-in-a-python-module
    # list the functions contanined in the 'slv_custom_functions' module
    functions_avalaible = getmembers(slv_custom_functions_mod, isfunction)
    # try to find the functions with that name
    for listed_function in functions_avalaible:
        if custom_function_name in listed_function:
            found_function = True
            break

    return found_function


def check_and_import_custom_function(function_name, custom_functions_name):
    '''
    Function to import the custom functions module and look for an specific function
    '''
    found_function = False
    slv_custom_functions_mod = check_and_import_the_custom_functions_module(
        custom_functions_name)
    if slv_custom_functions_mod is not None:
        found_function = find_custom_function(
            function_name, slv_custom_functions_mod)
    else:
        logger.warning("Custom Functions module not found")

    return found_function, slv_custom_functions_mod


def execute_custom_function_pre_post_processor(raw_input_output, custom_function_pre_post_processor, multi_ext_conn_mem,
                                               global_mem, conn_mem, ip, port, session_key, session_value,
                                               custom_functions_name):
    '''
    Function to execute the custom function preprocessor
    '''
    # Null check + initialization (if applies)
    if custom_function_pre_post_processor.Input is None:
        custom_function_pre_post_processor.Input = list()
    if custom_function_pre_post_processor.Output is None:
        custom_function_pre_post_processor.Output = list()

    # adding the input or output as the first parameter ti call the custom function (if not done previously)
    if not CUSTOM_FUNCTION_PROCESSORS_INPUT_OUTPUT in custom_function_pre_post_processor.Input:
        custom_function_pre_post_processor.Input.insert(
            0, CUSTOM_FUNCTION_PROCESSORS_INPUT_OUTPUT)
    if not CUSTOM_FUNCTION_PROCESSORS_INPUT_OUTPUT in custom_function_pre_post_processor.Output:
        custom_function_pre_post_processor.Output.insert(
            0, CUSTOM_FUNCTION_PROCESSORS_INPUT_OUTPUT)

    memory_mod_for_functions_multi_ext_conn_mem, memory_mod_for_functions_global, memory_mod_for_functions_conn, \
        results = custom_function_execution(custom_function_pre_post_processor, raw_input_output, multi_ext_conn_mem,
                                            global_mem, conn_mem, ip, port, session_key, session_value,
                                            custom_functions_name)

    # the first element has to be the processed input/output
    if results is not None:
        processed_input_output = results[0]
    else:
        processed_input_output = raw_input_output

    return memory_mod_for_functions_multi_ext_conn_mem, memory_mod_for_functions_global,\
        memory_mod_for_functions_conn, processed_input_output


def memory_operation_execution(biltin_mem_op, external_input_output, multi_ext_conn_mem,
                               global_mem, conn_mem, ip, port, session_key, session_value):
    '''
    Function to execute a builtin memory operation declared in a rule, returning the changes in
    terms of memory variables
    '''
    memory_mod_for_functions_multi_ext_conn_mem = dict()
    memory_mod_for_functions_global = dict()
    memory_mod_for_functions_conn = dict()

    operation = biltin_mem_op.Operation.upper()
    params = prepare_memory_operation_parameters(
        biltin_mem_op, external_input_output,
        multi_ext_conn_mem, global_mem, conn_mem,
        ip, port, session_key, session_value)
    output = do_memory_operation(operation, params)
    if len(output) > 0:
        memory_mod_for_functions_multi_ext_conn_mem, memory_mod_for_functions_global,\
            memory_mod_for_functions_conn = process_memory_operation_results(
                biltin_mem_op, output, multi_ext_conn_mem, global_mem, conn_mem)

    return (memory_mod_for_functions_multi_ext_conn_mem, memory_mod_for_functions_global,
            memory_mod_for_functions_conn)


def custom_function_execution(custom_function, external_input_output, multi_ext_conn_mem,
                              global_mem, conn_mem, ip, port, session_key, session_value,
                              custom_functions_name):
    '''
    Function to execute a custom function declared in a rule, returning the changes in
    terms of memory variables
    '''
    memory_mod_for_functions_multi_ext_conn_mem = dict()
    memory_mod_for_functions_global = dict()
    memory_mod_for_functions_conn = dict()
    results = None
    found_function, slv_custom_functions_mod = check_and_import_custom_function(
        custom_function.Name, custom_functions_name)

    if found_function:
        # https://stackoverflow.com/questions/11781265/python-using-getattr-to-call-function-with-variable-parameters
        try:
            params = prepare_memory_operation_parameters(custom_function, external_input_output, multi_ext_conn_mem,
                                                         global_mem, conn_mem, ip, port, session_key, session_value)
            results = getattr(slv_custom_functions_mod,
                              custom_function.Name)(*params)
            memory_mod_for_functions_multi_ext_conn_mem, memory_mod_for_functions_global,\
                memory_mod_for_functions_conn = process_memory_operation_results(
                    custom_function, results, multi_ext_conn_mem, global_mem, conn_mem)
        except:
            logger.exception(
                f"Error calling the custom function: '{custom_function.Name}' and/or processing "
                "the corresponding results")
    else:
        logger.warning(
            f"Custom function:{custom_function.Name} not found in the custom functions module")

    return (memory_mod_for_functions_multi_ext_conn_mem, memory_mod_for_functions_global,
            memory_mod_for_functions_conn, results)


def get_potential_memory_mods_using_bultin_mem_ops(conv_rules, external_input, multi_ext_conn_mem,
                                                   global_mem, conn_mem, ip, port, session_key,
                                                   session_value):
    '''
    Function to get memory modifications as results of the execution of bultin memory operations
    Builtin memory operation information within the rule   
        BuiltInMemOps struct {
            Enable    bool     
            Operation string   
            Input     []string 
            Output    []string   
        }
    '''
    # list (python dict) of potential modifications of memory variables.
    # In case there are several modifications applicable to
    # the same memory variable, the last one is applied
    memory_mod_for_functions_multi = dict()
    memory_mod_for_functions_global = dict()
    memory_mod_for_functions_conn = dict()

    if conv_rules is not None and len(conv_rules) > 0:
        # For each conversation rule
        for rule in conv_rules:
            if interlanguage_bool_check(rule.BuiltInMemOps.Enable):
                memory_mod_for_functions_multi, memory_mod_for_functions_global,\
                    memory_mod_for_functions_conn = memory_operation_execution(
                        rule.BuiltInMemOps, external_input, multi_ext_conn_mem,
                        global_mem, conn_mem, ip, port, session_key, session_value)

    return (memory_mod_for_functions_multi, memory_mod_for_functions_global,
            memory_mod_for_functions_conn)


def get_potential_memory_mods_using_custom_functions(conv_rules, external_input, multi_ext_conn_mem,
                                                     global_mem, conn_mem, ip, port, session_key,
                                                     session_value, custom_functions_name):
    '''
    Function to get memory modifications as results of the execution of custom functions
    Expected custom function information within the rule   
        CustomFunction struct {
            Enable bool     
            Name   string   
            Input  []string 
            Output []string 
        } 
    '''
    # list (python dict) of potential modifications of memory variables.
    # In case there are several modifications applicable to
    # the same memory variable, the last one is applied
    memory_mod_for_functions_multi = dict()
    memory_mod_for_functions_global = dict()
    memory_mod_for_functions_conn = dict()

    if conv_rules is not None and len(conv_rules) > 0:
        # For each conversation rule
        for rule in conv_rules:
            if interlanguage_bool_check(rule.CustomFunction.Enable):
                memory_mod_for_functions_multi, memory_mod_for_functions_global,\
                    memory_mod_for_functions_conn, _ = custom_function_execution(
                        rule.CustomFunction, external_input, multi_ext_conn_mem,
                        global_mem, conn_mem, ip, port, session_key, session_value,
                        custom_functions_name)

    return memory_mod_for_functions_multi, memory_mod_for_functions_global, memory_mod_for_functions_conn

# =========================================================================================
# Operation functions for managing incoming data
# =========================================================================================


def capture_data_using_rule(rule, recv_data):
    '''
    Function to extract information from the incoming data
    '''
    rule_data_captured = {
        RULE_ID: rule.Id,
        CAPTURES: dict()
    }
    # For each capture group
    if rule.Capturing.Captures is not None:
        for capture in rule.Capturing.Captures:

            # Capture regex in b64?
            if interlanguage_bool_check(capture.B64Flag):
                capt_ptrn = base64.b64decode(capture.Regex).decode("utf-8")
            else:
                capt_ptrn = capture.Regex

            # if not empty
            if len(capt_ptrn.pattern) > 0:
                # execution of the capturing regex
                hit = re.search(capt_ptrn, recv_data)
                if hit:
                    rule_data_captured[CAPTURES][capture.MemVarName] = hit.group(
                    )
                    logger.info(f"Data captured for the rule:{rule.Id} using the regex: " +
                                f"'{capture.Regex}' for the variable: '{capture.MemVarName}'")
            else:
                logger.warning(
                    f"The capturing regex for the rule:{rule.Id} is empty for the variable:" +
                    f" '{capture.MemVarName}'")

    return rule_data_captured


def check_data_and_rule(rule, recv_data):
    '''
    Function to check if an input from outside is detected by a conversation rule
    '''
    # Variable to return
    recv_data_applicable = False
    rule_data_captured = None

    if interlanguage_bool_check(rule.RegexBase64Flag):
        rule_ptrn = base64.b64decode(rule.Regex).decode("utf-8")
    else:
        rule_ptrn = rule.Regex

    if len(rule_ptrn.pattern) > 0:
        # execute the regex
        match = re.search(rule_ptrn, recv_data)
        if match:
            recv_data_applicable = True
            logger.info(
                f"The rule:{rule.Id} has been detected as 'applicable' for the received input")

            if interlanguage_bool_check(rule.Capturing.Enable):
                logger.info(f"Capturing data for the rule:{rule.Id}...")
                rule_data_captured = capture_data_using_rule(rule, recv_data)
    else:
        logger.warning(f"Rule:{rule.Id} has not a regex expression")

    return recv_data_applicable, rule_data_captured


def is_rule_applicable(rule, multi_ext_conn_mem, global_mem, conn_mem, recv_data):
    '''
    Function to check if a given conversation rule is applicable or not according to the input and 
    the memory status (multi, global and connection level)
    '''

    recv_data_applicable, rule_data_captured = check_data_and_rule(
        rule, recv_data)

    if recv_data_applicable:
        memory_apllicable = check_memory_and_rule(rule, multi_ext_conn_mem,
                                                  other_memory_1=global_mem, other_memory_2=conn_mem)
        applicable = recv_data_applicable and memory_apllicable
    else:
        applicable = False

    return applicable, rule_data_captured


def check_memory_conditions(memory_conditions, multi_ext_conn_mem, global_mem, conn_mem):
    '''
    Function to check the memory conditions are satisfied in a set of memory snapshots
    '''
    multi_ext_conn_memory_applicable, present_multi = check_one_memory_and_conditions(
        multi_ext_conn_mem, memory_conditions, other_memory_1=global_mem, other_memory_2=conn_mem)
    global_memory_applicable, present_global = check_one_memory_and_conditions(
        global_mem, memory_conditions, other_memory_1=multi_ext_conn_mem, other_memory_2=conn_mem)
    conn_memory_applicable, present_conn = check_one_memory_and_conditions(
        conn_mem, memory_conditions, other_memory_1=multi_ext_conn_mem, other_memory_2=global_mem)

    applicable = (
        (multi_ext_conn_memory_applicable and present_multi) or
        (global_memory_applicable and present_global) or
        (conn_memory_applicable and present_conn) or
        # or no conditions are present
        memory_conditions is None or
        len(memory_conditions) == 0)

    return applicable


def is_group_applicable(group, multi_ext_conn_mem, global_mem, conn_mem):
    '''
    Function to check if a given conversation group is applicable or not, according to 
    the memory status (multi, global and connection level)
    '''
    applicable = check_memory_conditions(
        group.MemConditions, multi_ext_conn_mem, global_mem, conn_mem)

    return applicable


def evaluate_rule_using_regex(rule, multi_ext_conn_mem, global_mem, conn_mem,
                              recv_data, regex_conv_rules, captured_data):
    '''
    Function to detect if a rule is 
    '''
    applicable = False
    if rule.Mode.lower() != ASYNC_MODE:
        applicable, rule_data_captured = is_rule_applicable(
            rule, multi_ext_conn_mem, global_mem, conn_mem, recv_data)

    if applicable:
        # Add the rule in the list of rules to execute
        regex_conv_rules.append(rule)
        logger.info(
            f"Detected applicable rule according to the input and memory. Rule:{rule.Id}")

        # If not null neither empty
        if rule_data_captured is not None and (len(rule_data_captured[CAPTURES]) > 0):
            captured_data.append(rule_data_captured)
    return applicable, regex_conv_rules, captured_data,


def detect_applicable_rules_using_rules_regex(rules, first_hit_applicable, multi_ext_conn_mem,
                                              global_mem, conn_mem, recv_data, regex_conv_rules,
                                              captured_data, first_hit, number_rule_checker_subworkers):
    '''
    Function to get the list of conversation rules applicables using rules (no groups)
    '''
    first_hit_applicable_scenario = interlanguage_bool_check(
        first_hit_applicable)

    # Not parallel rule checking to ensure first hit approach
    if first_hit_applicable_scenario:
        for rule in rules:
            applicable, regex_conv_rules, captured_data = evaluate_rule_using_regex(
                rule, multi_ext_conn_mem, global_mem, conn_mem,
                recv_data, regex_conv_rules, captured_data)

            # This will be executed in the first applicable rule, as well as in any loop.
            # But if the first the condition is applicable no more loops will be executed => BREAK
            # are we in the scenario of only the first hit, and the hit has already happened?
            first_hit = applicable and first_hit_applicable_scenario
            if first_hit:
                logger.info(
                    f"Since the flag 'conversation_use_only_first_hit' is enabled, " +
                    "no more rules will be detected")
                break
    else:
        # https://docs.python.org/3/library/concurrent.futures.html
        with concurrent.futures.ThreadPoolExecutor(max_workers=number_rule_checker_subworkers) as executor:
            future_results = [executor.submit(evaluate_rule_using_regex, rule, multi_ext_conn_mem, global_mem,
                                              conn_mem, recv_data, list(), list()) for rule in rules]
            done = False
            future_results_to_check = future_results

            while (not done):
                # reset the list for the next iteration
                next_iteration_future_results_to_check = list()

                for rule_result in future_results_to_check:
                    # is the result available, and still work to do?
                    if rule_result.done():
                        applicable, regex_conv_rules_for_rule, captured_data_for_rule = rule_result.result()
                        if applicable:
                            regex_conv_rules.extend(regex_conv_rules_for_rule)
                            captured_data.extend(captured_data_for_rule)
                    else:
                        next_iteration_future_results_to_check.append(
                            rule_result)

                # Check if all rules have been already checked (no rules to check in the next iteration)
                if len(next_iteration_future_results_to_check) == 0:
                    done = True
                else:
                    future_results_to_check = next_iteration_future_results_to_check

            if done:
                executor.shutdown()

    return regex_conv_rules, captured_data, first_hit


def detect_applicable_rules_using_rules_groups(cnv_rules, multi_ext_conn_mem,
                                               global_mem, conn_mem, recv_data, regex_conv_rules,
                                               captured_data, first_hit, number_rule_checker_subworkers):
    '''
    Function to get the list of conversation rules applicables using rules that are part of a group
    '''
    for group in cnv_rules.Conversation.CustomRules.Groups:
        regex_match_group = False
        memory_conditions_group = False

        if not first_hit:
            # Check if the group is applicable via Regex
            if group.Regex is not None and len(group.Regex.pattern) > 0:
                if interlanguage_bool_check(group.RegexBase64Flag):
                    rule_ptrn = base64.b64decode(group.Regex).decode("utf-8")
                else:
                    rule_ptrn = group.Regex
                regex_match_group = re.search(rule_ptrn, recv_data)

            # Check if the group is applicable via Memory variables
            if (group is not None and len(group.Rules) > 0 and
                    group.MemConditions is not None and len(group.MemConditions) > 0):
                memory_conditions_group = is_group_applicable(
                    group, multi_ext_conn_mem, global_mem, conn_mem)

            if regex_match_group or memory_conditions_group:
                logger.debug(
                    f"Conversation rule group '{group.Id}' detected as applicable. Is applicable for RegEx?'{regex_match_group}'. " +
                    f"Is applicable for memory conditions?'{memory_conditions_group}'")

                regex_conv_rules, captured_data, first_hit = detect_applicable_rules_using_rules_regex(
                    group.Rules, cnv_rules.ExtOperation.ConversationUseOnlyFirstHit, multi_ext_conn_mem,
                    global_mem, conn_mem, recv_data, regex_conv_rules,
                    captured_data, first_hit, number_rule_checker_subworkers)
        else:
            break  # If first_hit is applicable, just avoid checking additional groups

    return regex_conv_rules, captured_data, first_hit


def detect_applicable_rules_using_regex(cnv_rules, multi_ext_conn_mem, global_mem,
                                        conn_mem, recv_data, number_rule_checker_subworkers):
    '''
    Function to get the list of conversation rules applicables
    '''
    regex_conv_rules = list()
    captured_data = list()
    first_hit = False

    # Check rules
    regex_conv_rules, captured_data, first_hit = detect_applicable_rules_using_rules_regex(
        cnv_rules.Conversation.CustomRules.Rules, cnv_rules.ExtOperation.ConversationUseOnlyFirstHit,
        multi_ext_conn_mem, global_mem, conn_mem, recv_data, regex_conv_rules, captured_data, first_hit,
        number_rule_checker_subworkers)

    # Check groups
    if cnv_rules.Conversation.CustomRules.Groups is not None:
        regex_conv_rules, captured_data, first_hit = detect_applicable_rules_using_rules_groups(
            cnv_rules, multi_ext_conn_mem,
            global_mem, conn_mem, recv_data, regex_conv_rules,
            captured_data, first_hit, number_rule_checker_subworkers)

    return regex_conv_rules, captured_data


# =========================================================================================
# Operation functions for preparing outcoming data
# =========================================================================================


def get_parameter_value(parameter, multi_ext_conn_mem, global_mem, conn_mem, session_key,
                        session_value, ip, port):
    '''
    Function to find what is the value of a given parameter. First check the session key and value, 
    and IP & port
    '''
    if parameter.upper() == SESSION_KEY_PARAMETER:
        param_value = session_key
    elif parameter.upper() == SESSION_VALUE_PARAMETER:
        param_value = session_value
    elif parameter.upper() == IP_VALUE_PARAMETER:
        param_value = ip
    elif parameter.upper() == PORT_VALUE_PARAMETER:
        param_value = port
    # in case it is not the session key or value, then check if it exists in the global memory,
    # or in the connection memory
    elif parameter in multi_ext_conn_mem:
        param_value = multi_ext_conn_mem[parameter]
    elif parameter in global_mem:
        param_value = global_mem[parameter]
    elif parameter in conn_mem:
        param_value = conn_mem[parameter]
    else:
        param_value = None

    return param_value


def substitute_response_parameters(parameter_list, multi_ext_conn_mem, global_mem, conn_mem,
                                   session_key, session_value, ip, port, conn_id, response):
    '''
    Function to modify the response parameters for the values of the memory variables
    '''
    for parameter in parameter_list:
        # get parameter value
        paremeter_value = get_parameter_value(
            parameter, multi_ext_conn_mem, global_mem, conn_mem, session_key, session_value,
            ip, port)

        # substitute the paramater for the corresponding value (if not None/null)
        if parameter is not None:
            response = re.sub("{{"+parameter+"}}",
                              str(paremeter_value), response)
            logger.info(f"Detected parameter: '{parameter}' in the response for the connection:" +
                        f"{conn_id}, parameter value added: '{paremeter_value}'")
        else:
            logger.warning("The detected parameter in the response has no value to use! " +
                           f"Parameter: '{{{parameter}}}' " +
                           f"for the response:'{response}' in the connection:{conn_id}")

    return response


def add_response_parameters(response, multi_ext_conn_mem, global_mem, conn_mem, session_key,
                            session_value, conn_id, ip, port):
    '''
    Function to add the corresponding response parameters (if any). The response parameters
    are those that are between '{{' and '}}'
    '''
    parameters_pattern = "(?<={{)(.*?)(?=}})"
    parameter_list = re.findall(parameters_pattern, response)
    detected_parameters = len(parameter_list)

    while detected_parameters > 0:
        # result = [par1, par2, par3]
        response = substitute_response_parameters(parameter_list, multi_ext_conn_mem, global_mem,
                                                  conn_mem, session_key, session_value, ip, port,
                                                  conn_id, response)
        parameter_list = re.findall(parameters_pattern, response)
        detected_parameters = len(parameter_list)

    return response


def prepare_reply(response, response_b64_flag, multi_ext_conn_mem, global_mem, conn_mem,
                  session_key, session_value, conn_id, ip, port):
    '''
    Function to prepare the data to be sent as results of a detected conversation rule
    '''
    if interlanguage_bool_check(response_b64_flag):
        response = base64.b64decode(response).decode("utf-8")

    response = add_response_parameters(
        response, multi_ext_conn_mem, global_mem, conn_mem, session_key, session_value,
        conn_id, ip, port)

    return response

# =========================================================================================
# Operation functions for async rules
# =========================================================================================


def check_async_beginning_rule(rule):
    '''
    Function to detect if a given rule is an async (or hybrid) rule to be executed at the 
    beginning of the connection
    '''
    return rule.Mode.lower() != SYNC_MODE and interlanguage_bool_check(rule.BeginningAsyncRule)
