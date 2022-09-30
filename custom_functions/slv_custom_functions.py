"""
Sec Lope De Vega external connector
=================================================
Module: slv_custom_functions.py
Author: Alberto Dominguez 

This is module is an examplary module for testing how custom functions work
"""

import logging

# logger
logger = logging.getLogger(__name__)


def testing_preprocessor(external_input):
    '''
    Just to put put in the logs the external input received and modify a bolean value
    '''
    logger.info(f"Input received in preprocessor function:{external_input}")
    return external_input


def testing_function(external_input, boolean):
    '''
    Just to put put in the logs the external input received and modify a bolean value
    '''
    logger.info(f"Input received in custom function:{external_input}")
    return not boolean


def neo_test(external_input, float, int, boolean):
    '''
    Custom function for test neo conversation rules
    '''
    logger.info(f"Input received in custom function:{external_input}")
    string = external_input
    float = float + 1.5
    int = int + 5
    boolean = not boolean
    return string, float, int, boolean


def neo_preprocessor(external_input, input_counter):
    '''
    Custom function that works as preprocessor for test neo conversation rules
    '''
    external_input_proc = external_input.replace("\n","") + "_prepocessor_check"
    input_counter += 1
    return external_input_proc, input_counter


def neo_postprocessor(external_output, output_counter):
    '''
    Custom function that works as postprocessor for test neo conversation rules
    '''
    output_counter += 1
    return external_output, output_counter
