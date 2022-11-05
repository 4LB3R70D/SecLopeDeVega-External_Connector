"""
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega external connector
=================================================
Module: interoperability_py_go.py
Author: Alberto Dominguez 

This module contains the logic to ensure that data coming from go 
is managed correctly in python, or preparing python variables to be used
in go
"""

import logging
import re

# logger
logger = logging.getLogger(__name__)

# regex for number transformation
int_regex = re.compile("([-+]?[0-9.]+)")
float_regex = re.compile("([-+]?[0-9.]+)")

# GO / PYTHON interoperability
GO_BOOL_TRUE = "true"
GO_BOOL_FALSE = "false"

BOOL = "bool"
INT = "int"
FLOAT = "float"
STRING = "string"


def interlanguage_bool_check(value_to_check):
    '''
    Auxiliary function to check if a value is True either in Go or Python
    '''
    return (isinstance(value_to_check, bool) and value_to_check) or (value_to_check == GO_BOOL_TRUE)


def convert_py_bool_to_go_bool(value_to_transform):
    '''
    Auxiliary function to transform a python boolean value to a go boolean value
    '''
    if value_to_transform:
        go_bool_value = GO_BOOL_TRUE
    else:
        go_bool_value = GO_BOOL_FALSE
    return go_bool_value


def get_python_type(mem_variable_type):
    '''
    Function to get the python type from a memory variable declaration
    '''
    # variable to return
    py_type = str
    # make it lower case
    mem_variable_type = mem_variable_type.lower()

    if mem_variable_type.lower() == BOOL:
        py_type = bool
    elif mem_variable_type.lower() == INT:
        py_type = int
    elif mem_variable_type.lower() == FLOAT:
        py_type = float

    return py_type


def get_pythonic_value(type_to_transform, value_to_transform):
    '''
    Function to transform or check if the rule memory variable is a python
    variable with the corresponding data type. If the value to transform/check
    is not in the corresponding format, neither in a string format; no
    transformation will be done. In oother words, only those values that are
    in a string format will be changed if they don't fit the right data type
    It only the following variables python data types:
        - bool
        - int
        - float
        - string (default)
    '''
    transformed_value = None
    current_data_type = type(value_to_transform)
    transformation_error_message = (f"Value:{value_to_transform} " +
                                    f"with the data type:{current_data_type} " +
                                    f"not transformed into {type_to_transform}")
    try:
        # X --> X
        if type_to_transform is current_data_type:
            transformed_value = value_to_transform

        # String --> Bool
        elif type_to_transform is bool and\
                current_data_type is str:
            transformed_value = (
                value_to_transform.lower() == GO_BOOL_TRUE)

        # String --> Int
        elif type_to_transform is int and\
                current_data_type is str:
            # Non-number characters are removed (only numbers remains)
            hit = re.search(int_regex, value_to_transform)
            if hit:
                value_to_transform_string_int = hit.group()
                transformed_value = int(value_to_transform_string_int)
            else:
                logger.warning(
                    f"Error transforming the value: '{value_to_transform}' to 'int'")

        # String --> Float
        elif type_to_transform is float and\
                current_data_type is str:
            # Non-number characters are removed (only numbers and point symbol remain)
            hit = re.search(float_regex, value_to_transform)
            if hit:
                value_to_transform_string_float_number = hit.group()
                # Ensure only one point is present. if many, split the text and
                # only get the first two parts
                value_to_transform_splitted_text = value_to_transform_string_float_number.split(
                    ".")
                if len(value_to_transform_splitted_text) > 1:
                    value_to_transform_only_one_point = "".join(
                        (value_to_transform_splitted_text[0], ".", value_to_transform_splitted_text[1]))
                else:
                    value_to_transform_only_one_point = value_to_transform_splitted_text[0]
                # transform the prepared string into a float
                transformed_value = float(value_to_transform_only_one_point)
            else:
                logger.warning(
                    f"Error transforming the value: '{value_to_transform}'- to 'float'")

        # Int or Bool --> Float
        elif type_to_transform is float and (
                current_data_type is int or current_data_type is bool):
            transformed_value = float(value_to_transform)

        # Float or Bool --> Int
        elif type_to_transform is int and (
                current_data_type is float or current_data_type is bool):
            transformed_value = int(value_to_transform)

        # Float or Int --> Bool
        elif type_to_transform is bool and (
                current_data_type is float or current_data_type is int):
            transformed_value = bool(value_to_transform)

        # Float or Int or Bool --> String
        elif type_to_transform is str:
            transformed_value = str(value_to_transform)

        # No transformation: X--> None
        else:
            logger.warning(transformation_error_message)
    except:
        logger.exception(transformation_error_message)

    return transformed_value
