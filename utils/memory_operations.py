"""
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega external connector
=================================================
Module: memory_operations.py
Author: Alberto Dominguez 

This module contains auxiliary functionalities pertaining memory operations support
"""
import base64
import logging
import statistics
import re

# logger
logger = logging.getLogger(__name__)

# Built-in memory operations
STR_CONCAT = "STR_CONCAT"  # STR => STR
STR_REPLACE = "STR_REPLACE"  # STR => STR
STR_SUBTRACT = "STR_SUBTRACT"  # STR => STR
STR_UPPER = "STR_UPPER"  # STR => STR
STR_LOWER = "STR_LOWER"  # STR => STR
STR_SPLIT = "STR_SPLIT"  # STR => STR
STR_TRIM = "STR_TRIM"  # STR => STR
STR_MATCH = "STR_MATCH"  # STR => BOOL
STR_CAPTURE = "STR_CAPTURE"  # STR => STR
STR_COUNT = "STR_COUNT"  # STR => NBR
STR_MODE = "STR_MODE"  # STR => STR
STR_ENCODE_B64 = "STR_ENCODE_B64"  # STR => STR
STR_DECODE_B64 = "STR_DECODE_B64"  # STR => STR
STR_ENCODE_HEX = "STR_ENCODE_HEX"  # STR => STR
STR_DECODE_HEX = "STR_DECODE_HEX"  # STR => STR

NBR_SUM = "NBR_SUM"  # NBR => NBR
NBR_SUBTRACT = "NBR_SUBTRACT"  # NBR => NBR
NBR_MULTIPLY = "NBR_MULTIPLY"  # NBR => NBR
NBR_DIVIDE = "NBR_DIVIDE"  # NBR => NBR
NBR_FLOOR = "NBR_FLOOR"  # NBR => NBR
NBR_MODULO = "NBR_MODULO"  # NBR => NBR
NBR_POWER = "NBR_POWER"  # NBR => NBR
NBR_INVERSE_SIGN = "NBR_INVERSE_SIGN"  # NBR => NBR
NBR_GREATER = "NBR_GREATER"  # NBR => BOOL
NBR_LOWER = "NBR_LOWER"  # NBR => BOOL
NBR_GREATEREQ = "NBR_GREATEREQ"  # NBR => BOOL
NBR_LOWEREQ = "NBR_LOWEREQ"  # NBR => BOOL
NBR_MEAN = "NBR_MEAN"  # NBR => NBR
NBR_GEOMETRIC_MEAN = "NBR_GEOMETRIC_MEAN"  # NBR => NBR
NBR_HARMONIC_MEAN = "NBR_HARMONIC_MEAN"  # NBR => NBR
NBR_MEDIAN = "NBR_MEDIAN"  # NBR => NBR
NBR_MEDIAN_LOW = "NBR_MEDIAN_LOW"  # NBR => NBR
NBR_MEDIAN_HIGH = "NBR_MEDIAN_HIGH"  # NBR => NBR
NBR_MEDIAN_GROUPED = "NBR_MEDIAN_GROUPED"  # NBR => NBR
NBR_MODE = "NBR_MODE"  # NBR => NBR
NBR_POP_STD_DEV = "NBR_POP_STD_DEV"  # NBR => NBR
NBR_STD_DEV = "NBR_STD_DEV"  # NBR => NBR
NBR_POP_VAR = "NBR_POP_VAR"  # NBR => NBR
NBR_VAR = "NBR_VAR"  # NBR => NBR

LGC_NOT = "LGC_NOT"  # BOOL => BOOL
LGC_AND = "LGC_AND"  # BOOL => BOOL
LGC_OR = "LGC_OR"  # BOOL => BOOL
LGC_XOR = "LGC_XOR"  # BOOL => BOOL
LGC_NAND = "LGC_NAND"  # BOOL => BOOL
LGC_NOR = "LGC_NOR"  # BOOL => BOOL

BASE_OPERATION_ELEMENT = 0
ADDITIONAL_OPERATION_ELEMENT = 1
SECOND_ADDITIONAL_OPERATION_ELEMENT = 2
SINGLE_OPERATION_PARAMETER = 1
DUPLE_OPERATION_PARAMETERS = 2
TRIPLE_OPERATION_PARAMETERS = 3


def compare_two_memory_variables_values(variable_to_compare_value, reference_variable_value):
    '''
    Auxiliary function to compare the content of two memory variables
    '''
    result = False
    string_comparison = False

    if type(variable_to_compare_value) == type(reference_variable_value):
        string_comparison = type(variable_to_compare_value) == str
        if not string_comparison:
            # string comparison happens later
            result = variable_to_compare_value == reference_variable_value

    # different types => comparison in string format
    elif variable_to_compare_value is not None and reference_variable_value is not None:
        variable_to_compare_value = str(variable_to_compare_value)
        reference_variable_value = str(reference_variable_value)
        string_comparison = True

    if string_comparison:
        result = variable_to_compare_value.upper() == reference_variable_value.upper()

    return result


def do_memory_operation(operation, input):
    '''
    Auxiliary method to do the memory built-in operations
    '''
    results = list()
    operation_done = False
    
    def logic_and(input):
        '''
        internal funcion for doing an AND operation
        '''
        operation_result = None
        first_element = True
        for element in input:
            if isinstance(element, bool):
                if first_element:
                    operation_result = element
                    first_element = False
                else:
                    operation_result &= element
                operation_done = True
        return operation_result, operation_done
        
    def logic_or(input):
        '''
        internal function for doing an OR operation
        '''
        operation_result = None
        first_element = True
        for element in input:
            if isinstance(element, bool):
                if first_element:
                    operation_result = element
                    first_element = False
                else:
                    operation_result |= element
                operation_done = True
        return operation_result, operation_done

    if operation == STR_CONCAT:
        operation_result = "".join(input)
        results.append(operation_result)

    elif operation == STR_REPLACE:
        if len(input) >= TRIPLE_OPERATION_PARAMETERS:
            operation_result = re.sub(
                input[ADDITIONAL_OPERATION_ELEMENT],
                input[SECOND_ADDITIONAL_OPERATION_ELEMENT],
                input[BASE_OPERATION_ELEMENT])
            results.append(operation_result)
            operation_done = True

    elif operation == STR_SUBTRACT:
        if len(input) >= DUPLE_OPERATION_PARAMETERS:
            operation_result = input[BASE_OPERATION_ELEMENT].replace(
                input[ADDITIONAL_OPERATION_ELEMENT], "")
            results.append(operation_result)
            operation_done = True

    elif operation == STR_UPPER:
        if len(input) >= SINGLE_OPERATION_PARAMETER:
            operation_result = input[BASE_OPERATION_ELEMENT].upper()
            results.append(operation_result)
            operation_done = True

    elif operation == STR_LOWER:
        if len(input) >= SINGLE_OPERATION_PARAMETER:
            operation_result = input[BASE_OPERATION_ELEMENT].lower()
            results.append(operation_result)
            operation_done = True

    elif operation == STR_SPLIT:
        if len(input) >= DUPLE_OPERATION_PARAMETERS:
            results = input[BASE_OPERATION_ELEMENT].split(
                input[ADDITIONAL_OPERATION_ELEMENT])
            operation_done = True

    elif operation == STR_TRIM:
        if len(input) >= SINGLE_OPERATION_PARAMETER:
            operation_result = input[BASE_OPERATION_ELEMENT].strip()
            results.append(operation_result)
            operation_done = True

    elif operation == STR_MATCH:
        if len(input) >= DUPLE_OPERATION_PARAMETERS:
            match = re.search(
                input[ADDITIONAL_OPERATION_ELEMENT],
                input[BASE_OPERATION_ELEMENT])
            operation_result = match is not None
            results.append(operation_result)
            operation_done = True

    elif operation == STR_CAPTURE:
        if len(input) >= DUPLE_OPERATION_PARAMETERS:
            match = re.search(
                input[ADDITIONAL_OPERATION_ELEMENT],
                input[BASE_OPERATION_ELEMENT])
            operation_result = match.group()
            results.append(operation_result)
            operation_done = True

    elif operation == STR_COUNT:
        if len(input) >= SINGLE_OPERATION_PARAMETER:
            operation_result = len(input[BASE_OPERATION_ELEMENT])
            results.append(operation_result)
            operation_done = True

    elif operation == STR_MODE:
        operation_result = None
        if all(isinstance(n, str) for n in input):
            operation_result = statistics.mode(input)
        results.append(operation_result)
        operation_done = True

    elif operation == STR_ENCODE_B64:
        operation_result = None
        if all(isinstance(n, str) for n in input):
            results = [
                base64.b64encode(
                    str(i).encode()
                ).decode("utf-8")
                for i in input]
            operation_done = True

    elif operation == STR_DECODE_B64:
        operation_result = None
        if all(isinstance(n, str) for n in input):
            try:
                results = [
                    base64.b64decode(
                        str(i).encode()
                    ).decode("utf-8")
                    for i in input]
                operation_done = True
            except:
                logger.exception(
                    "Error using a decode ba64 built-in memory operation")

    elif operation == STR_ENCODE_HEX:
        operation_result = None
        if all(isinstance(n, str) for n in input):
            results = [
                str(i).encode("utf-8").hex()
                for i in input]
            operation_done = True

    elif operation == STR_DECODE_HEX:
        operation_result = None
        if all(isinstance(n, str) for n in input):
            try:
                results = [
                    bytes.fromhex(i).decode("utf-8")
                    for i in input]
                operation_done = True
            except:
                logger.exception(
                    "Error using a decode hexadecimal built-in memory operation")

    elif operation == NBR_SUM:
        operation_result = 0
        for element in input:
            if isinstance(element, int) or isinstance(element, float):
                operation_result += element
                operation_done = True
        results.append(operation_result)

    elif operation == NBR_SUBTRACT:
        operation_result = 0
        first_element = True
        for element in input:
            if isinstance(element, int) or isinstance(element, float):
                if first_element:
                    operation_result = element
                    first_element = False
                else:
                    operation_result -= element
                operation_done = True
        results.append(operation_result)

    elif operation == NBR_MULTIPLY:
        operation_result = 1
        for element in input:
            if isinstance(element, int) or isinstance(element, float):
                operation_result *= element
                operation_done = True
        results.append(operation_result)

    elif operation == NBR_DIVIDE:
        operation_result = 0
        first_element = True
        for element in input:
            if isinstance(element, int) or isinstance(element, float):
                if first_element:
                    operation_result = element
                    first_element = False
                else:
                    operation_result /= element
                operation_done = True
        results.append(operation_result)

    elif operation == NBR_MODULO:
        operation_result = 0
        first_element = True
        for element in input:
            if isinstance(element, int) or isinstance(element, float):
                if first_element:
                    operation_result = element
                    first_element = False
                else:
                    operation_result %= element
                operation_done = True
        results.append(operation_result)

    elif operation == NBR_FLOOR:
        operation_result = 0
        first_element = True
        for element in input:
            if isinstance(element, int) or isinstance(element, float):
                if first_element:
                    operation_result = element
                    first_element = False
                else:
                    operation_result //= element
                operation_done = True
        results.append(operation_result)

    elif operation == NBR_INVERSE_SIGN:
        if (len(input) >= SINGLE_OPERATION_PARAMETER and
                (isinstance(input[BASE_OPERATION_ELEMENT], int) or
                 isinstance(input[BASE_OPERATION_ELEMENT], float))):
            operation_result = input[BASE_OPERATION_ELEMENT]*-1
            results.append(operation_result)
            operation_done = True

    elif operation == NBR_POWER:
        operation_result = 0
        first_element = True
        for element in input:
            if isinstance(element, int) or isinstance(element, float):
                if first_element:
                    operation_result = element
                    first_element = False
                else:
                    operation_result **= element
                operation_done = True
        results.append(operation_result)

    elif operation == NBR_GREATER:
        if (len(input) >= DUPLE_OPERATION_PARAMETERS and
            (isinstance(input[BASE_OPERATION_ELEMENT], int) or
             isinstance(input[BASE_OPERATION_ELEMENT], float)) and
                (isinstance(input[ADDITIONAL_OPERATION_ELEMENT], int) or
                 isinstance(input[ADDITIONAL_OPERATION_ELEMENT], float))):
            operation_result = input[BASE_OPERATION_ELEMENT] > input[ADDITIONAL_OPERATION_ELEMENT]
            results.append(operation_result)
            operation_done = True

    elif operation == NBR_LOWER:
        if (len(input) >= DUPLE_OPERATION_PARAMETERS and
            (isinstance(input[BASE_OPERATION_ELEMENT], int) or
             isinstance(input[BASE_OPERATION_ELEMENT], float)) and
                (isinstance(input[ADDITIONAL_OPERATION_ELEMENT], int) or
                 isinstance(input[ADDITIONAL_OPERATION_ELEMENT], float))):
            operation_result = input[BASE_OPERATION_ELEMENT] < input[ADDITIONAL_OPERATION_ELEMENT]
            results.append(operation_result)
            operation_done = True

    elif operation == NBR_GREATEREQ:
        if (len(input) >= DUPLE_OPERATION_PARAMETERS and
            (isinstance(input[BASE_OPERATION_ELEMENT], int) or
             isinstance(input[BASE_OPERATION_ELEMENT], float)) and
                (isinstance(input[ADDITIONAL_OPERATION_ELEMENT], int) or
                 isinstance(input[ADDITIONAL_OPERATION_ELEMENT], float))):
            operation_result = input[BASE_OPERATION_ELEMENT] >= input[ADDITIONAL_OPERATION_ELEMENT]
            results.append(operation_result)
            operation_done = True

    elif operation == NBR_LOWEREQ:
        if (len(input) >= DUPLE_OPERATION_PARAMETERS and
            (isinstance(input[BASE_OPERATION_ELEMENT], int) or
             isinstance(input[BASE_OPERATION_ELEMENT], float)) and
                (isinstance(input[ADDITIONAL_OPERATION_ELEMENT], int) or
                 isinstance(input[ADDITIONAL_OPERATION_ELEMENT], float))):
            operation_result = input[BASE_OPERATION_ELEMENT] <= input[ADDITIONAL_OPERATION_ELEMENT]
            results.append(operation_result)
            operation_done = True

    elif operation == NBR_MEAN:
        operation_result = None
        if all((isinstance(n, int) or isinstance(n, float)) for n in input):
            operation_result = statistics.mean(input)
            operation_done = True
        results.append(operation_result)

    elif operation == NBR_GEOMETRIC_MEAN:
        operation_result = None
        if all((isinstance(n, int) or isinstance(n, float)) for n in input):
            operation_result = statistics.geometric_mean(input)
            operation_done = True
        results.append(operation_result)

    elif operation == NBR_HARMONIC_MEAN:
        operation_result = None
        if all((isinstance(n, int) or isinstance(n, float)) for n in input):
            operation_result = statistics.harmonic_mean(input)
            operation_done = True
        results.append(operation_result)

    elif operation == NBR_MEDIAN:
        operation_result = None
        if all((isinstance(n, int) or isinstance(n, float)) for n in input):
            operation_result = statistics.median(input)
            operation_done = True
        results.append(operation_result)

    elif operation == NBR_MEDIAN_HIGH:
        operation_result = None
        if all((isinstance(n, int) or isinstance(n, float)) for n in input):
            operation_result = statistics.median_high(input)
            operation_done = True
        results.append(operation_result)

    elif operation == NBR_MEDIAN_LOW:
        operation_result = None
        if all((isinstance(n, int) or isinstance(n, float)) for n in input):
            operation_result = statistics.median_low(input)
            operation_done = True
        results.append(operation_result)

    elif operation == NBR_MEDIAN_GROUPED:
        operation_result = None
        if all((isinstance(n, int) or isinstance(n, float)) for n in input):
            operation_result = statistics.median_grouped(input)
            operation_done = True
        results.append(operation_result)

    elif operation == NBR_MODE:
        operation_result = None
        if all((isinstance(n, int) or isinstance(n, float)) for n in input):
            operation_result = statistics.mode(input)
            operation_done = True
        results.append(operation_result)

    elif operation == NBR_POP_STD_DEV:
        operation_result = None
        if all((isinstance(n, int) or isinstance(n, float)) for n in input):
            operation_result = statistics.pstdev(input)
            operation_done = True
        results.append(operation_result)

    elif operation == NBR_STD_DEV:
        operation_result = None
        if all((isinstance(n, int) or isinstance(n, float)) for n in input):
            operation_result = statistics.stdev(input)
            operation_done = True
        results.append(operation_result)

    elif operation == NBR_POP_VAR:
        operation_result = None
        if all((isinstance(n, int) or isinstance(n, float)) for n in input):
            operation_result = statistics.pvariance(input)
            operation_done = True
        results.append(operation_result)

    elif operation == NBR_VAR:
        operation_result = None
        if all((isinstance(n, int) or isinstance(n, float)) for n in input):
            operation_result = statistics.variance(input)
            operation_done = True
        results.append(operation_result)

    elif operation == LGC_NOT:
        if (len(input) >= SINGLE_OPERATION_PARAMETER and
                (isinstance(input[BASE_OPERATION_ELEMENT], bool))):
            operation_result = not input[BASE_OPERATION_ELEMENT]
            results.append(operation_result)
            operation_done = True

    elif operation == LGC_AND:
        operation_result, operation_done = logic_and(input)
        results.append(operation_result)

    elif operation == LGC_OR:
        operation_result, operation_done = logic_or(input)
        results.append(operation_result)

    elif operation == LGC_XOR:
        operation_result = None
        first_element = True
        for element in input:
            if isinstance(element, bool):
                if first_element:
                    operation_result = element
                    first_element = False
                else:
                    operation_result ^= element
                operation_done = True
        results.append(operation_result)

    elif operation == LGC_NAND:
        operation_result, operation_done = logic_and(input)
        operation_result = not operation_result
        results.append(operation_result)

    elif operation == LGC_NOR:
        operation_result, operation_done = logic_or(input)
        operation_result = not operation_result
        results.append(operation_result)

    else:
        logger.warning(f"Operation: '{operation}' not recognised")

    if not operation_done:
        logger.warning(f"Operation: '{operation}' cannot be done, " +
                       "insufficient number of input parameters or not the right data type")

    return results
