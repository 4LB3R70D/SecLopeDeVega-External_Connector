"""
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega external connector
=================================================
Module: todo_list.py
Author: Alberto Dominguez 

This module contains code related to the ToDo list to know when and 
how a converstation rule should be executed. This object is threat safe
"""

import logging
import threading
import time

import logic_modules.conversation_module as conv_mod

# logger
logger = logging.getLogger(__name__)

# Constants
TRIGGERING_RULE_IN_RULE_TUPLE = 0
DELAY_IN_RULE_TUPLE = 1
ASYNC_RULE_IN_RULE_TUPLE = 2


class ToDo:
    '''
    Object for each entry to add in the todo list
    '''

    def __init__(self, todo_id, conn_id, rule_to_execute, delay, triggering_rule,
                 loop_id):
        self.id = todo_id
        self.execution_time = time.time() + delay
        self.connection_id = conn_id
        self.rule_to_execute = rule_to_execute
        self.triggering_rule = triggering_rule
        self.completed = False
        self.loop_id = loop_id  # in case this todo is linked with an async loop


class Loop:
    '''
    Object for each entry to add in the loop list
    '''

    def __init__(self, loop_id, conn_id, loop_info, triggering_rule, async_rule_tuple_list_loop):
        self.id = loop_id
        self.triggering_rule = triggering_rule
        self.conn_id = conn_id
        self.async_rule_tuple_list_loop = async_rule_tuple_list_loop
        self.conditions = loop_info.Conditions
        
        # rule iteration counters: Key=rule_id, value=max_iteration
        self.rule_iteration_max_list = dict()
        # initialization of the counters
        for conditional_rule in loop_info.ConditionalRules:
            self.rule_iteration_max_list[conditional_rule.RuleID] = conditional_rule.MaxNumberIterations

        # rule iteration counters: Key=rule_id, value=counter
        self.rule_iteration_counter_list = dict()
        # initialization of the counters
        for async_rule_tuple in async_rule_tuple_list_loop:
            self.rule_iteration_counter_list[async_rule_tuple[ASYNC_RULE_IN_RULE_TUPLE].Id] = 0


class ToDoList:

    def __init__(self, connection_register):
        self.lock = threading.Lock()
        # for async tasks (ToDos)
        self.todo_list = set()
        self.id_counter_todos = 1
        # for loops
        self.loop_list = set()
        self.id_counter_loops = 1
        self.connection_register = connection_register

    # ---------------------
    # ToDos
    # ---------------------
    def get_new_todo_id(self):
        '''
        Function to get a new connection ID & update the ID counter
        of the connection register
        '''
        with self.lock:
            new_id = self.id_counter_todos
            self.id_counter_todos += 1
        return new_id

    def add_new_todo(self, conn_id, rule_tuple, loop_id=0):
        '''
        Function to add a new 'ToDo' in the list. The rule tuple received has the following format:
        (ID triggering rule[if any], delay, rule to execute)
        '''

        add_todo_flag = True

        # if async loop case, really checks if we need to add the rule
        if loop_id > 0:
            add_todo_flag = self.check_and_update_loop_rule_iteration_counter(
                loop_id, rule_tuple[ASYNC_RULE_IN_RULE_TUPLE].Id)

        if add_todo_flag:
            new_id = self.get_new_todo_id()
            new_todo = ToDo(new_id, conn_id, rule_tuple[ASYNC_RULE_IN_RULE_TUPLE],
                            rule_tuple[DELAY_IN_RULE_TUPLE],
                            rule_tuple[TRIGGERING_RULE_IN_RULE_TUPLE], loop_id)
            with self.lock:
                self.todo_list.add(new_todo)

            logger.info(f"Added a new ToDo in the list to execute the rule:{rule_tuple[ASYNC_RULE_IN_RULE_TUPLE].Id}, " +
                        f"with the ID:{new_id} for the connection:{conn_id}. The rule was triggered by the rule: " +
                        f"{rule_tuple[TRIGGERING_RULE_IN_RULE_TUPLE]}")

    def get_todos_to_execute(self):
        '''
        Function to get all the 'ToDos' to execute
        '''
        todos_to_do = set()
        now = time.time()

        with self.lock:
            todo_list_copy = self.todo_list.copy()

        for current_todo in todo_list_copy:
            # For each 'ToDo' not completed and the executing time is reached or exceeded
            if not current_todo.completed and now >= current_todo.execution_time:
                # Add the todo in the list to execute
                todos_to_do.add(current_todo)

                with self.lock:
                    # Remove from the global list
                    self.todo_list.remove(current_todo)

                logger.info(
                    f"Detected the ToDo:'{current_todo.id}', to be executed using the " +
                    f"conversation rule:'{current_todo.rule_to_execute.Id}' (if memory conditions are " +
                    f"applicable and they are met). The async loop of this ToDo is:'{current_todo.loop_id}' " +
                    "('0' means there is not an async loop behind this ToDo)")

                # In case this ToDo is part of a loop, check if the loop should go for the next iteration
                if current_todo.loop_id > 0:
                    self.next_loop_iteration(current_todo)

        return todos_to_do

    # ---------------------
    # Async Loops
    # ---------------------

    def get_new_loop_id(self):
        '''
        Function to get a new connection ID & update the ID counter
        of the connection register
        '''
        with self.lock:
            new_id = self.id_counter_loops
            self.id_counter_loops += 1
        return new_id

    def get_loop(self, loop_id):
        '''
        Method to get the loop given a loop id
        '''
        found_loop = None
        with self.lock:
            for loop in self.loop_list:
                if loop.id == loop_id:
                    found_loop = loop
                    logger.debug(f"Found the loop with the ID:'{loop_id}'")
                    break

        return found_loop

    def check_and_update_loop_rule_iteration_counter(self, loop_id, rule_id):
        '''
        Method to check and update the rule iteration counter of a given
        loop and rule
        '''
        everything_ok = False
        
        with self.lock:
            # find the loop
            for loop in self.loop_list:
                if loop.id == loop_id:
                    
                    # check the max number of iterations
                    # if it is in use
                    if loop.rule_iteration_max_list[rule_id] > 0:
                        loop.rule_iteration_counter_list[rule_id] += 1
                        if loop.rule_iteration_counter_list[rule_id] <= loop.rule_iteration_max_list[rule_id]:
                            everything_ok = True
                    else:
                        everything_ok = True
                    break
                        
        return everything_ok

    def check_loop_conditions_ok(self, loop):
        '''
        Mehtod to check if given a loop, the loop conditions are met or not
        '''
        ok = False
        if loop is not None:
            multi_ext_conn_mem = self.connection_register.get_copy_multi_ext_connectors_memory()
            global_mem = self.connection_register.get_copy_global_memory()
            conn_mem = self.connection_register.get_copy_conn_memory(
                loop.conn_id)

            ok = conv_mod.check_memory_conditions(
                loop.conditions,
                multi_ext_conn_mem, global_mem, conn_mem)

        return ok

    def add_todos_from_loop(self, loop, specific_rule_id_to_add=None):
        '''
        Method to add new ToDos based on the loop information. If rule_of_the_loop_id
        is 'None', this means all rules of the loop should be added in the ToDo list.
        If it is not None, only one specific rule will be added in the loop
        '''
        for rule_tuple in loop.async_rule_tuple_list_loop:
            if (specific_rule_id_to_add is None or
                    rule_tuple[ASYNC_RULE_IN_RULE_TUPLE].Id == specific_rule_id_to_add):
                self.add_new_todo(loop.conn_id, rule_tuple, loop_id=loop.id)

    def add_async_loop(self, conn_id, loop_info, triggering_rule, async_rule_tuple_list_loop):
        '''
        Method to add a new async loop if the corresponding memory conditions are met. 
        It returns a boolena value to say if the async loop was added in the list or not
        (depending on the memory conditions)
        '''
        loop_id = self.get_new_loop_id()
        new_loop = Loop(loop_id, conn_id, loop_info,
                        triggering_rule, async_rule_tuple_list_loop)

        # Check memory conditions of the loop
        if self.check_loop_conditions_ok(new_loop):

            with self.lock:
                self.loop_list.add(new_loop)

            logger.info(
                f"Added a new async loop in the list, with the ID:'{loop_id}' " +
                f"for the connection:'{conn_id}'. The loop was triggered by the rule: " +
                f"'{triggering_rule}'")

            # add the new todos to add in the list
            self.add_todos_from_loop(new_loop)

        # New loop created but not saved since memory conditions are not satisfied
        else:
            logger.info(
                f"A new async loop cannot be added in the list with the ID:{loop_id} " +
                f"for the connection:'{conn_id}' triggered by the rule: " +
                f"{triggering_rule}. Memory conditions are not met")

    def remove_async_loop(self, loop_id):
        '''
        Method to remove a loop from the the list of async loops
        '''
        with self.lock:
            for loop in self.loop_list:
                if loop.id == loop_id:
                    self.loop_list.remove(loop)
                    logger.info(
                        f"The loop with the ID:'{loop_id}' has been removed from the loop list" +
                        " since its conditions are no longer valid")
                    break

    def next_loop_iteration(self, todo):
        '''
        Method to do the next loop iteration if applicable, given a ToDo to execute
        '''
        loop = self.get_loop(todo.loop_id)

        if loop is not None:
            if self.check_loop_conditions_ok(loop):
                # Next loop iteration
                self.add_todos_from_loop(loop, todo.rule_to_execute.Id)
            else:
                # Stop the loop
                self.remove_async_loop(todo.loop_id)
        else:
            logger.warning(
                f"The loop with the ID:'{todo.loop_id}' not found!")
