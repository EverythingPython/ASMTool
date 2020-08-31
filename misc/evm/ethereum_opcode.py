import collections
from math import *

stack = collections.stack()

# FF:
# general int is 256bit, aka -2**255 ... 2**256-1
# other type obey 256bit as an element
# but also support bit 8, 16 and so on
# for overflow it goes to 1 (wrap)


def isAllReal():
    # a symbolic or concolic
    pass


# Symbolically executing an instruction
def sym_exec_ins(params, block, instr, func_call, current_func_name):
    global MSIZE
    global visited_pcs
    global solver
    global vertices
    global edges
    global g_src_map
    global calls_affect_state
    global data_source

    stack = params.stack
    mem = params.mem
    memory = params.memory
    state = params.state
    sha3_list = params.sha3_list
    path_conditions_and_vars = params.path_conditions_and_vars
    analysis = params.analysis
    calls = params.calls
    overflow_pcs = params.overflow_pcs

    visited_pcs.add(state["pc"])

    instr_parts = str.split(instr, ' ')
    opcode = instr_parts[0]

    if opcode == "INVALID":
        return
    else:
        opcode_mapper[opcode]()


def OP_ASSERTFAIL():
    if g_src_map:
        source_code = g_src_map.get_source_code(state['pc'])
        source_code = source_code.split("(")[0]
        func_name = source_code.strip()
        if check_sat(solver, False) != unsat:
            model = solver.model()
        if func_name == "assert":
            global_problematic_pcs["assertion_failure"].append(
                Assertion(state["pc"], model))
        elif func_call != -1:
            global_problematic_pcs["assertion_failure"].append(
                Assertion(func_call, model))
    return


# collecting the analysis result by calling this skeletal function
# this should be done before symbolically executing the instruction,
# since SE will modify the stack and mem
update_analysis(analysis, opcode, stack, mem, state,
                path_conditions_and_vars, solver)
if opcode == "CALL" and analysis["reentrancy_bug"] and analysis["reentrancy_bug"][-1]:
    global_problematic_pcs["reentrancy_bug"].append(state["pc"])

log.debug("==============================")
log.debug("EXECUTING: " + instr)

#
#  0s: Stop and Arithmetic Operations
#


def OP_STOP():
    state.pc += 1
    # FF: do a stop return 
    return stop


def OP_ADD():
    if len(stack) > 1:
        state.pc += 1
        first = stack.pop()
        second = stack.pop()
        # Type conversion is needed when they are mismatched
        if isReal(first) and isSymbolic(second):
            first = BitVecVal(first, 256)
            computed = first + second
        elif isSymbolic(first) and isReal(second):
            second = BitVecVal(second, 256)
            computed = first + second
        else:
            # both are real and we need to manually modulus with 2 ** 256
            # if both are symbolic z3 takes care of modulus automatically
            computed = (first + second) % (2 ** 256)
        computed = simplify(computed) if is_expr(computed) else computed

        check_revert = False
        if jump_type[block] == 'conditional':
            jump_target = vertices[block].get_jump_target()
            falls_to = vertices[block].get_falls_to()
            check_revert = any([True for instruction in vertices[jump_target].get_instructions(
            ) if instruction.startswith('REVERT')])
            if not check_revert:
                check_revert = any([True for instruction in vertices[falls_to].get_instructions(
                ) if instruction.startswith('REVERT')])

        if jump_type[block] != 'conditional' or not check_revert:
            if not isAllReal(computed, first):
                solver.push()
                solver.add(UGT(first, computed))
                if check_sat(solver) == sat:
                    global_problematic_pcs['integer_overflow'].append(
                        Overflow(state['pc'] - 1, solver.model()))
                    overflow_pcs.append(state['pc'] - 1)
                solver.pop()

        stack.push(computed)
    else:
        raise ValueError('STACK underflow')


def OP_MUL():
    if len(stack) > 1:
        state.pc += 1
        first = stack.pop()
        second = stack.pop()
        if isReal(first) and isSymbolic(second):
            first = BitVecVal(first, 256)
        elif isSymbolic(first) and isReal(second):
            second = BitVecVal(second, 256)
        computed = first * second & UNSIGNED_BOUND_NUMBER
        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)
    else:
        raise ValueError('STACK underflow')


def OP_SUB():
    if len(stack) > 1:
        state.pc += 1
        first = stack.pop()
        second = stack.pop()
        if isReal(first) and isSymbolic(second):
            first = BitVecVal(first, 256)
            computed = first - second
        elif isSymbolic(first) and isReal(second):
            second = BitVecVal(second, 256)
            computed = first - second
        else:
            computed = (first - second) % (2 ** 256)
        computed = simplify(computed) if is_expr(computed) else computed

        check_revert = False
        if jump_type[block] == 'conditional':
            jump_target = vertices[block].get_jump_target()
            falls_to = vertices[block].get_falls_to()
            check_revert = any([True for instruction in vertices[jump_target].get_instructions(
            ) if instruction.startswith('REVERT')])
            if not check_revert:
                check_revert = any([True for instruction in vertices[falls_to].get_instructions(
                ) if instruction.startswith('REVERT')])

        if jump_type[block] != 'conditional' or not check_revert:
            if not isAllReal(first, second):
                solver.push()
                solver.add(UGT(second, first))
                if check_sat(solver) == sat:
                    global_problematic_pcs['integer_underflow'].append(
                        Underflow(state['pc'] - 1, solver.model()))
                solver.pop()

        stack.push(computed)
    else:
        raise ValueError('STACK underflow')


def OP_DIV():
    if len(stack) > 1:
        state.pc += 1
        first = stack.pop()
        second = stack.pop()
        if isAllReal(first, second):
            if second == 0:
                computed = 0
            else:
                first = to_unsigned(first)
                second = to_unsigned(second)
                computed = first / second
        else:
            first = to_symbolic(first)
            second = to_symbolic(second)
            solver.push()
            solver.add(Not(second == 0))
            if check_sat(solver) == unsat:
                computed = 0
            else:
                computed = UDiv(first, second)
            solver.pop()
        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)
    else:
        raise ValueError('STACK underflow')


def OP_SDIV():
    if len(stack) > 1:
        state.pc += 1
        first = stack.pop()
        second = stack.pop()
        if isAllReal(first, second):
            first = to_signed(first)
            second = to_signed(second)
            if second == 0:
                computed = 0
            elif first == -2**255 and second == -1:
                computed = -2**255
            else:
                sign = -1 if (first / second) < 0 else 1
                computed = sign * (abs(first) / abs(second))
        else:
            first = to_symbolic(first)
            second = to_symbolic(second)
            solver.push()
            solver.add(Not(second == 0))
            if check_sat(solver) == unsat:
                computed = 0
            else:
                solver.push()
                solver.add(Not(And(first == -2**255, second == -1)))
                if check_sat(solver) == unsat:
                    computed = -2**255
                else:
                    solver.push()
                    solver.add(first / second < 0)
                    sign = -1 if check_sat(solver) == sat else 1

                    def z3_abs(x): return If(x >= 0, x, -x)
                    first = z3_abs(first)
                    second = z3_abs(second)
                    computed = sign * (first / second)
                    solver.pop()
                solver.pop()
            solver.pop()
        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)
    else:
        raise ValueError('STACK underflow')


def OP_MOD():
    if len(stack) > 1:
        state.pc += 1
        first = stack.pop()
        second = stack.pop()
        if isAllReal(first, second):
            if second == 0:
                computed = 0
            else:
                first = to_unsigned(first)
                second = to_unsigned(second)
                computed = first % second & UNSIGNED_BOUND_NUMBER

        else:
            first = to_symbolic(first)
            second = to_symbolic(second)

            solver.push()
            solver.add(Not(second == 0))
            if check_sat(solver) == unsat:
                # it is provable that second is indeed equal to zero
                computed = 0
            else:
                computed = URem(first, second)
            solver.pop()

        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)
    else:
        raise ValueError('STACK underflow')


def OP_SMOD():
    if len(stack) > 1:
        state.pc += 1
        first = stack.pop()
        second = stack.pop()
        if isAllReal(first, second):
            if second == 0:
                computed = 0
            else:
                first = to_signed(first)
                second = to_signed(second)
                sign = -1 if first < 0 else 1
                computed = sign * (abs(first) % abs(second))
        else:
            first = to_symbolic(first)
            second = to_symbolic(second)

            solver.push()
            solver.add(Not(second == 0))
            if check_sat(solver) == unsat:
                # it is provable that second is indeed equal to zero
                computed = 0
            else:

                solver.push()
                solver.add(first < 0)  # check sign of first element
                sign = BitVecVal(-1, 256) if check_sat(solver) == sat \
                    else BitVecVal(1, 256)
                solver.pop()

                def z3_abs(x): return If(x >= 0, x, -x)
                first = z3_abs(first)
                second = z3_abs(second)

                computed = sign * (first % second)
            solver.pop()

        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)
    else:
        raise ValueError('STACK underflow')


def OP_ADDMOD():
    if len(stack) > 2:
        state.pc += 1
        first = stack.pop()
        second = stack.pop()
        third = stack.pop()

        if isAllReal(first, second, third):
            if third == 0:
                computed = 0
            else:
                computed = (first + second) % third
        else:
            first = to_symbolic(first)
            second = to_symbolic(second)
            solver.push()
            solver.add(Not(third == 0))
            if check_sat(solver) == unsat:
                computed = 0
            else:
                first = ZeroExt(256, first)
                second = ZeroExt(256, second)
                third = ZeroExt(256, third)
                computed = (first + second) % third
                computed = Extract(255, 0, computed)
            solver.pop()
        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)
    else:
        raise ValueError('STACK underflow')


def OP_MULMOD():
    if len(stack) > 2:
        state.pc += 1
        first = stack.pop()
        second = stack.pop()
        third = stack.pop()

        if isAllReal(first, second, third):
            if third == 0:
                computed = 0
            else:
                computed = (first * second) % third
        else:
            first = to_symbolic(first)
            second = to_symbolic(second)
            solver.push()
            solver.add(Not(third == 0))
            if check_sat(solver) == unsat:
                computed = 0
            else:
                first = ZeroExt(256, first)
                second = ZeroExt(256, second)
                third = ZeroExt(256, third)
                computed = URem(first * second, third)
                computed = Extract(255, 0, computed)
            solver.pop()
        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)
    else:
        raise ValueError('STACK underflow')


def OP_EXP():
    if len(stack) > 1:
        state.pc += 1
        base = stack.pop()
        exponent = stack.pop()
        # Type conversion is needed when they are mismatched
        if isAllReal(base, exponent):
            computed = pow(base, exponent, 2**256)  # FF: wrap for overflow
        else:
            # The computed value is unknown, this is because power is
            # not supported in bit-vector theory
            new_var_name = gen.gen_arbitrary_var()
            computed = BitVec(new_var_name, 256)
        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)
    else:
        raise ValueError('STACK underflow')


def OP_SIGNEXTEND():
    if len(stack) > 1:
        state.pc += 1
        first = stack.pop()
        second = stack.pop()
        if isAllReal(first, second):
            if first >= 32 or first < 0:
                computed = second
            else:
                signbit_index_from_right = 8 * first + 7
                # FF : signed ext for negative
                if second & (1 << signbit_index_from_right):
                    computed = second | (
                        2 ** 256 - (1 << signbit_index_from_right))
                else:
                    computed = second & ((1 << signbit_index_from_right) - 1)
        else:
            first = to_symbolic(first)
            second = to_symbolic(second)
            solver.push()
            solver.add(Not(Or(first >= 32, first < 0)))
            if check_sat(solver) == unsat:
                computed = second
            else:
                signbit_index_from_right = 8 * first + 7
                solver.push()
                solver.add(second & (1 << signbit_index_from_right) == 0)
                if check_sat(solver) == unsat:
                    computed = second | (
                        2 ** 256 - (1 << signbit_index_from_right))
                else:
                    computed = second & ((1 << signbit_index_from_right) - 1)
                solver.pop()
            solver.pop()
        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)
    else:
        raise ValueError('STACK underflow')
#
#  10s: Comparison and Bitwise Logic Operations
#


def OP_LT():
    if len(stack) > 1:
        state.pc += 1
        first = stack.pop()
        second = stack.pop()
        if isAllReal(first, second):
            first = to_unsigned(first)
            second = to_unsigned(second)
            if first < second:
                computed = 1
            else:
                computed = 0
        else:
            computed = If(ULT(first, second), BitVecVal(
                1, 256), BitVecVal(0, 256))
        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)
    else:
        raise ValueError('STACK underflow')


def OP_GT():
    if len(stack) > 1:
        state.pc += 1
        first = stack.pop()
        second = stack.pop()
        if isAllReal(first, second):
            first = to_unsigned(first)
            second = to_unsigned(second)
            if first > second:
                computed = 1
            else:
                computed = 0
        else:
            computed = If(UGT(first, second), BitVecVal(
                1, 256), BitVecVal(0, 256))
        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)
    else:
        raise ValueError('STACK underflow')


def OP_SLT():  # Not fully faithful to signed comparison
    if len(stack) > 1:
        state.pc += 1
        first = stack.pop()
        second = stack.pop()
        if isAllReal(first, second):
            first = to_signed(first)
            second = to_signed(second)
            if first < second:
                computed = 1
            else:
                computed = 0
        else:
            computed = If(first < second, BitVecVal(1, 256), BitVecVal(0, 256))
        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)
    else:
        raise ValueError('STACK underflow')


def OP_SGT():  # Not fully faithful to signed comparison
    if len(stack) > 1:
        state.pc += 1
        first = stack.pop()
        second = stack.pop()
        if isAllReal(first, second):
            first = to_signed(first)
            second = to_signed(second)
            if first > second:
                computed = 1
            else:
                computed = 0
        else:
            computed = If(first > second, BitVecVal(1, 256), BitVecVal(0, 256))
        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)
    else:
        raise ValueError('STACK underflow')


def OP_EQ():
    if len(stack) > 1:
        state.pc += 1
        first = stack.pop()
        second = stack.pop()
        if isAllReal(first, second):
            if first == second:
                computed = 1
            else:
                computed = 0
        else:
            computed = If(first == second, BitVecVal(
                1, 256), BitVecVal(0, 256))
        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)
    else:
        raise ValueError('STACK underflow')


def OP_ISZERO():
    # Tricky: this instruction works on both boolean and integer,
    # when we have a symbolic expression, type error might occur
    # Currently handled by try and catch
    if len(stack) > 0:
        state.pc += 1
        first = stack.pop()
        if isReal(first):
            if first == 0:
                computed = 1
            else:
                computed = 0
        else:
            computed = If(first == 0, BitVecVal(1, 256), BitVecVal(0, 256))
        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)
    else:
        raise ValueError('STACK underflow')


def OP_AND():
    if len(stack) > 1:
        state.pc += 1
        first = stack.pop()
        second = stack.pop()
        computed = first & second
        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)
    else:
        raise ValueError('STACK underflow')


def OP_OR():
    if len(stack) > 1:
        state.pc += 1
        first = stack.pop()
        second = stack.pop()

        computed = first | second
        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)

    else:
        raise ValueError('STACK underflow')


def OP_XOR():
    if len(stack) > 1:
        state.pc += 1
        first = stack.pop()
        second = stack.pop()

        computed = first ^ second
        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)

    else:
        raise ValueError('STACK underflow')


def OP_NOT():
    if len(stack) > 0:
        state.pc += 1
        first = stack.pop()
        computed = (~first) & UNSIGNED_BOUND_NUMBER
        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)
    else:
        raise ValueError('STACK underflow')


def OP_BYTE():
    if len(stack) > 1:
        state.pc += 1
        first = stack.pop()
        byte_index = 32 - first - 1
        second = stack.pop()

        # FF: each element goes with 256 bit, 32*8 bit
        if isAllReal(first, second):
            if first >= 32 or first < 0:
                computed = 0
            else:
                computed = second & (255 << (8 * byte_index))
                computed = computed >> (8 * byte_index)
        else:
            first = to_symbolic(first)
            second = to_symbolic(second)
            solver.push()
            solver.add(Not(Or(first >= 32, first < 0)))
            if check_sat(solver) == unsat:
                computed = 0
            else:
                computed = second & (255 << (8 * byte_index))
                computed = computed >> (8 * byte_index)
            solver.pop()
        computed = simplify(computed) if is_expr(computed) else computed
        stack.push(computed)
    else:
        raise ValueError('STACK underflow')
#
# 20s: SHA3
#


def OP_SHA3():
    if len(stack) > 1:
        state.pc += 1
        s0 = stack.pop()
        s1 = stack.pop()
        if isAllReal(s0, s1):
            # simulate the hashing of sha3
            data = [str(x) for x in memory[s0: s0 + s1]]
            position = ''.join(data)
            position = re.sub('[\s+]', '', position)
            position = zlib.compress(six.b(position), 9)
            position = base64.b64encode(position)
            position = position.decode('utf-8', 'strict')
            if position in sha3_list:
                stack.push(sha3_list[position])
            else:
                new_var_name = gen.gen_arbitrary_var()
                new_var = BitVec(new_var_name, 256)
                sha3_list[position] = new_var
                stack.push(new_var)
        else:
            # push into the execution a fresh symbolic variable
            new_var_name = gen.gen_arbitrary_var()
            new_var = BitVec(new_var_name, 256)
            path_conditions_and_vars[new_var_name] = new_var
            stack.push(new_var)
    else:
        raise ValueError('STACK underflow')
#
# 30s: Environment Information
#


def OP_ADDRESS():  # get address of currently executing account
    state.pc += 1
    stack.push(path_conditions_and_vars["Ia"])


def OP_BALANCE():
    if len(stack) > 0:
        state.pc += 1
        address = stack.pop()
        if isReal(address) and global_params.USE_GLOBAL_BLOCKCHAIN:
            new_var = data_source.getBalance(address)
        else:
            new_var_name = gen.gen_balance_var()
            if new_var_name in path_conditions_and_vars:
                new_var = path_conditions_and_vars[new_var_name]
            else:
                new_var = BitVec(new_var_name, 256)
                path_conditions_and_vars[new_var_name] = new_var
        if isReal(address):
            hashed_address = "concrete_address_" + str(address)
        else:
            hashed_address = str(address)
        state["balance"][hashed_address] = new_var
        stack.push(new_var)
    else:
        raise ValueError('STACK underflow')


def OP_CALLER():  # get caller address
    # that is directly responsible for this execution
    state.pc += 1
    stack.push(state["sender_address"])


def OP_ORIGIN():  # get execution origination address
    state.pc += 1
    stack.push(state["origin"])


def OP_CALLVALUE():  # get value of this transaction
    state.pc += 1
    stack.push(state["value"])


def OP_CALLDATALOAD():  # from input data from environment
    if len(stack) > 0:
        state.pc += 1
        position = stack.pop()
        if g_src_map:
            source_code = g_src_map.get_source_code(state['pc'] - 1)
            if source_code.startswith("function") and isReal(position) and current_func_name in g_src_map.func_name_to_params:
                params = g_src_map.func_name_to_params[current_func_name]
                param_idx = (position - 4) // 32
                for param in params:
                    if param_idx == param['position']:
                        new_var_name = param['name']
                        g_src_map.var_names.append(new_var_name)
            else:
                new_var_name = gen.gen_data_var(position)
        else:
            new_var_name = gen.gen_data_var(position)
        if new_var_name in path_conditions_and_vars:
            new_var = path_conditions_and_vars[new_var_name]
        else:
            new_var = BitVec(new_var_name, 256)
            path_conditions_and_vars[new_var_name] = new_var
        stack.push(new_var)
    else:
        raise ValueError('STACK underflow')


def OP_CALLDATASIZE():
    state.pc += 1
    new_var_name = gen.gen_data_size()
    if new_var_name in path_conditions_and_vars:
        new_var = path_conditions_and_vars[new_var_name]
    else:
        new_var = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = new_var
    stack.push(new_var)


def OP_CALLDATACOPY():  # Copy input data to memory
    #  TODO: Don't know how to simulate this yet
    if len(stack) > 2:
        state.pc += 1
        stack.pop()
        stack.pop()
        stack.pop()
    else:
        raise ValueError('STACK underflow')


def OP_CODESIZE():
    if g_disasm_file.endswith('.disasm'):
        evm_file_name = g_disasm_file[:-7]
    else:
        evm_file_name = g_disasm_file
    with open(evm_file_name, 'r') as evm_file:
        evm = evm_file.read()[:-1]
        code_size = len(evm) / 2
        stack.push(code_size)


def OP_CODECOPY():
    if len(stack) > 2:
        state.pc += 1
        mem_location = stack.pop()
        code_from = stack.pop()
        no_bytes = stack.pop()
        current_miu_i = state["miu_i"]

        if isAllReal(mem_location, current_miu_i, code_from, no_bytes):
            if six.PY2:
                temp = long(math.ceil((mem_location + no_bytes) / float(32)))
            else:
                temp = int(math.ceil((mem_location + no_bytes) / float(32)))

            if temp > current_miu_i:
                current_miu_i = temp

            if g_disasm_file.endswith('.disasm'):
                evm_file_name = g_disasm_file[:-7]
            else:
                evm_file_name = g_disasm_file
            with open(evm_file_name, 'r') as evm_file:
                evm = evm_file.read()[:-1]
                start = code_from * 2
                end = start + no_bytes * 2
                code = evm[start: end]
            mem[mem_location] = int(code, 16)
        else:
            new_var_name = gen.gen_code_var("Ia", code_from, no_bytes)
            if new_var_name in path_conditions_and_vars:
                new_var = path_conditions_and_vars[new_var_name]
            else:
                new_var = BitVec(new_var_name, 256)
                path_conditions_and_vars[new_var_name] = new_var

            temp = ((mem_location + no_bytes) / 32) + 1
            current_miu_i = to_symbolic(current_miu_i)
            expression = current_miu_i < temp
            solver.push()
            solver.add(expression)
            if MSIZE:
                if check_sat(solver) != unsat:
                    current_miu_i = If(expression, temp, current_miu_i)
            solver.pop()
            mem.clear()  # very conservative
            mem[str(mem_location)] = new_var
        state["miu_i"] = current_miu_i
    else:
        raise ValueError('STACK underflow')


def OP_RETURNDATACOPY():
    if len(stack) > 2:
        state["pc"] += 1
        stack.pop()
        stack.pop()
        stack.pop()
    else:
        raise ValueError('STACK underflow')


def OP_RETURNDATASIZE():
    state["pc"] += 1
    new_var_name = gen.gen_arbitrary_var()
    new_var = BitVec(new_var_name, 256)
    stack.push(new_var)


def OP_GASPRICE():
    state.pc += 1
    stack.push(state["gas_price"])


def OP_EXTCODESIZE():
    if len(stack) > 0:
        state.pc += 1
        address = stack.pop()
        if isReal(address) and global_params.USE_GLOBAL_BLOCKCHAIN:
            code = data_source.getCode(address)
            stack.push(len(code) / 2)
        else:
            # not handled yet
            new_var_name = gen.gen_code_size_var(address)
            if new_var_name in path_conditions_and_vars:
                new_var = path_conditions_and_vars[new_var_name]
            else:
                new_var = BitVec(new_var_name, 256)
                path_conditions_and_vars[new_var_name] = new_var
            stack.push(new_var)
    else:
        raise ValueError('STACK underflow')


def OP_EXTCODECOPY():
    if len(stack) > 3:
        state.pc += 1
        address = stack.pop()
        mem_location = stack.pop()
        code_from = stack.pop()
        no_bytes = stack.pop()
        current_miu_i = state["miu_i"]

        if isAllReal(address, mem_location, current_miu_i, code_from, no_bytes) and USE_GLOBAL_BLOCKCHAIN:
            if six.PY2:
                temp = long(math.ceil((mem_location + no_bytes) / float(32)))
            else:
                temp = int(math.ceil((mem_location + no_bytes) / float(32)))
            if temp > current_miu_i:
                current_miu_i = temp

            evm = data_source.getCode(address)
            start = code_from * 2
            end = start + no_bytes * 2
            code = evm[start: end]
            mem[mem_location] = int(code, 16)
        else:
            new_var_name = gen.gen_code_var(address, code_from, no_bytes)
            if new_var_name in path_conditions_and_vars:
                new_var = path_conditions_and_vars[new_var_name]
            else:
                new_var = BitVec(new_var_name, 256)
                path_conditions_and_vars[new_var_name] = new_var

            temp = ((mem_location + no_bytes) / 32) + 1
            current_miu_i = to_symbolic(current_miu_i)
            expression = current_miu_i < temp
            solver.push()
            solver.add(expression)
            if MSIZE:
                if check_sat(solver) != unsat:
                    current_miu_i = If(expression, temp, current_miu_i)
            solver.pop()
            mem.clear()  # very conservative
            mem[str(mem_location)] = new_var
        state["miu_i"] = current_miu_i
    else:
        raise ValueError('STACK underflow')
#
#  40s: Block Information
#


def OP_BLOCKHASH():  # information from block header
    if len(stack) > 0:
        state.pc += 1
        stack.pop()
        new_var_name = "IH_blockhash"
        if new_var_name in path_conditions_and_vars:
            new_var = path_conditions_and_vars[new_var_name]
        else:
            new_var = BitVec(new_var_name, 256)
            path_conditions_and_vars[new_var_name] = new_var
        stack.push(new_var)
    else:
        raise ValueError('STACK underflow')


def OP_COINBASE():  # information from block header
    state.pc += 1
    stack.push(state["currentCoinbase"])


def OP_TIMESTAMP():  # information from block header
    state.pc += 1
    stack.push(state["currentTimestamp"])


def OP_NUMBER():  # information from block header
    state.pc += 1
    stack.push(state["currentNumber"])


def OP_DIFFICULTY():  # information from block header
    state.pc += 1
    stack.push(state["currentDifficulty"])


def OP_GASLIMIT():  # information from block header
    state.pc += 1
    stack.push(state["currentGasLimit"])
#
#  50s: Stack, Memory, Storage, and Flow Information
#


def OP_POP():
    if len(stack) > 0:
        state.pc += 1
        stack.pop()
    else:
        raise ValueError('STACK underflow')


def OP_MLOAD():
    if len(stack) > 0:
        state.pc += 1
        address = stack.pop()
        current_miu_i = state["miu_i"]
        if isAllReal(address, current_miu_i) and address in mem:
            if six.PY2:
                temp = long(math.ceil((address + 32) / float(32)))
            else:
                temp = int(math.ceil((address + 32) / float(32)))
            if temp > current_miu_i:
                current_miu_i = temp
            value = mem[address]
            stack.push(value)
        else:
            temp = ((address + 31) / 32) + 1
            current_miu_i = to_symbolic(current_miu_i)
            expression = current_miu_i < temp
            solver.push()
            solver.add(expression)
            if MSIZE:
                if check_sat(solver) != unsat:
                    # this means that it is possibly that current_miu_i < temp
                    current_miu_i = If(expression, temp, current_miu_i)
            solver.pop()
            new_var_name = gen.gen_mem_var(address)
            if new_var_name in path_conditions_and_vars:
                new_var = path_conditions_and_vars[new_var_name]
            else:
                new_var = BitVec(new_var_name, 256)
                path_conditions_and_vars[new_var_name] = new_var
            stack.push(new_var)
            if isReal(address):
                mem[address] = new_var
            else:
                mem[str(address)] = new_var
        state["miu_i"] = current_miu_i
    else:
        raise ValueError('STACK underflow')


def OP_MSTORE():
    if len(stack) > 1:
        state.pc += 1
        stored_address = stack.pop()
        stored_value = stack.pop()
        current_miu_i = state["miu_i"]
        if isReal(stored_address):
            # preparing data for hashing later
            old_size = len(memory) // 32
            new_size = ceil32(stored_address + 32) // 32
            mem_extend = (new_size - old_size) * 32
            memory.extend([0] * mem_extend)
            value = stored_value
            for i in range(31, -1, -1):
                memory[stored_address + i] = value % 256
                value /= 256
        if isAllReal(stored_address, current_miu_i):
            if six.PY2:
                temp = long(math.ceil((stored_address + 32) / float(32)))
            else:
                temp = int(math.ceil((stored_address + 32) / float(32)))
            if temp > current_miu_i:
                current_miu_i = temp
            # note that the stored_value could be symbolic
            mem[stored_address] = stored_value
        else:
            temp = ((stored_address + 31) / 32) + 1
            expression = current_miu_i < temp
            solver.push()
            solver.add(expression)
            if MSIZE:
                if check_sat(solver) != unsat:
                    # this means that it is possibly that current_miu_i < temp
                    current_miu_i = If(expression, temp, current_miu_i)
            solver.pop()
            mem.clear()  # very conservative
            mem[str(stored_address)] = stored_value
        state["miu_i"] = current_miu_i
    else:
        raise ValueError('STACK underflow')


def OP_MSTORE8():
    if len(stack) > 1:
        state.pc += 1
        stored_address = stack.pop()
        temp_value = stack.pop()
        stored_value = temp_value % 256  # get the least byte
        current_miu_i = state["miu_i"]
        if isAllReal(stored_address, current_miu_i):
            if six.PY2:
                temp = long(math.ceil((stored_address + 1) / float(32)))
            else:
                temp = int(math.ceil((stored_address + 1) / float(32)))
            if temp > current_miu_i:
                current_miu_i = temp
            # note that the stored_value could be symbolic
            mem[stored_address] = stored_value
        else:
            temp = (stored_address / 32) + 1
            if isReal(current_miu_i):
                current_miu_i = BitVecVal(current_miu_i, 256)
            expression = current_miu_i < temp
            solver.push()
            solver.add(expression)
            if MSIZE:
                if check_sat(solver) != unsat:
                    # this means that it is possibly that current_miu_i < temp
                    current_miu_i = If(expression, temp, current_miu_i)
            solver.pop()
            mem.clear()  # very conservative
            mem[str(stored_address)] = stored_value
        state["miu_i"] = current_miu_i
    else:
        raise ValueError('STACK underflow')


def OP_SLOAD():
    if len(stack) > 0:
        state.pc += 1
        position = stack.pop()
        if isReal(position) and position in state["Ia"]:
            value = state["Ia"][position]
            stack.push(value)
        elif global_params.USE_GLOBAL_STORAGE and isReal(position) and position not in state["Ia"]:
            value = data_source.getStorageAt(position)
            state["Ia"][position] = value
            stack.push(value)
        else:
            if str(position) in state["Ia"]:
                value = state["Ia"][str(position)]
                stack.push(value)
            else:
                if is_expr(position):
                    position = simplify(position)
                if g_src_map:
                    new_var_name = g_src_map.get_source_code(
                        state['pc'] - 1)
                    operators = '[-+*/%|&^!><=]'
                    new_var_name = re.compile(operators).split(
                        new_var_name)[0].strip()
                    new_var_name = g_src_map.get_parameter_or_state_var(
                        new_var_name)
                    if new_var_name:
                        new_var_name = gen.gen_owner_store_var(
                            position, new_var_name)
                    else:
                        new_var_name = gen.gen_owner_store_var(position)
                else:
                    new_var_name = gen.gen_owner_store_var(position)

                if new_var_name in path_conditions_and_vars:
                    new_var = path_conditions_and_vars[new_var_name]
                else:
                    new_var = BitVec(new_var_name, 256)
                    path_conditions_and_vars[new_var_name] = new_var
                stack.push(new_var)
                if isReal(position):
                    state["Ia"][position] = new_var
                else:
                    state["Ia"][str(position)] = new_var
    else:
        raise ValueError('STACK underflow')


def OP_SSTORE():
    if len(stack) > 1:
        for call_pc in calls:
            calls_affect_state[call_pc] = True
        state.pc += 1
        stored_address = stack.pop()
        stored_value = stack.pop()
        if isReal(stored_address):
            # note that the stored_value could be unknown
            state["Ia"][stored_address] = stored_value
        else:
            # note that the stored_value could be unknown
            state["Ia"][str(stored_address)] = stored_value
    else:
        raise ValueError('STACK underflow')


def OP_JUMP():
    if len(stack) > 0:
        target_address = stack.pop()
        if isSymbolic(target_address):
            try:
                target_address = int(str(simplify(target_address)))
            except:
                raise TypeError("Target address must be an integer")
        vertices[block].set_jump_target(target_address)
        if target_address not in edges[block]:
            edges[block].append(target_address)
    else:
        raise ValueError('STACK underflow')


def OP_JUMPI():
    # We need to prepare two branches
    if len(stack) > 1:
        target_address = stack.pop()
        if isSymbolic(target_address):
            try:
                target_address = int(str(simplify(target_address)))
            except:
                raise TypeError("Target address must be an integer")
        vertices[block].set_jump_target(target_address)
        flag = stack.pop()
        branch_expression = (BitVecVal(0, 1) == BitVecVal(1, 1))
        if isReal(flag):
            if flag != 0:
                branch_expression = True
        else:
            branch_expression = (flag != 0)
        vertices[block].set_branch_expression(branch_expression)
        if target_address not in edges[block]:
            edges[block].append(target_address)
    else:
        raise ValueError('STACK underflow')


def OP_PC():
    stack.push(state["pc"])
    state.pc += 1


def OP_MSIZE():
    state.pc += 1
    msize = 32 * state["miu_i"]
    stack.push(msize)


def OP_GAS():
    # In general, we do not have this precisely. It depends on both
    # the initial gas and the amount has been depleted
    # we need o think about this in the future, in case precise gas
    # can be tracked
    state.pc += 1
    new_var_name = gen.gen_gas_var()
    new_var = BitVec(new_var_name, 256)
    path_conditions_and_vars[new_var_name] = new_var
    stack.push(new_var)


def OP_JUMPDEST():
    # Literally do nothing
    state.pc += 1
#
#  60s & 70s: Push Operations
#


def PUSH(n):
    # elif opcode.startswith('PUSH', 0):  # this is a push instruction
    position = int(opcode[4:], 10)
    state.pc += 1 + position
    pushed_value = int(instr_parts[1], 16)
    stack.push(pushed_value)
    if global_params.UNIT_TEST == 3:  # test evm symbolic
        stack[0] = BitVecVal(stack[0], 256)
#
#  80s: Duplication Operations
#


def DUP(n):
    # elif opcode.startswith("DUP", 0):
    state.pc += 1
    position = int(opcode[3:], 10) - 1
    if len(stack) > position:
        duplicate = stack[position]
        stack.push(duplicate)
    else:
        raise ValueError('STACK underflow')

#
#  90s: Swap Operations
#


def SWAP(n):
    # elif opcode.startswith("SWAP", 0):
    state.pc += 1
    position = int(opcode[4:], 10)
    if len(stack) > position:
        temp = stack[position]
        stack[position] = stack[0]
        stack[0] = temp
    else:
        raise ValueError('STACK underflow')

#
#  a0s: Logging Operations
#


def LOG(n):
    # elif opcode in ("LOG0", "LOG1", "LOG2", "LOG3", "LOG4"):
    state.pc += 1
    # We do not simulate these log operations
    num_of_pops = 2 + int(opcode[3:])
    while num_of_pops > 0:
        stack.pop()
        num_of_pops -= 1

#
#  f0s: System Operations
#


def OP_CREATE():
    if len(stack) > 2:
        state["pc"] += 1
        stack.pop()
        stack.pop()
        stack.pop()
        new_var_name = gen.gen_arbitrary_var()
        new_var = BitVec(new_var_name, 256)
        stack.push(new_var)
    else:
        raise ValueError('STACK underflow')


def OP_CALL():
    # TODO: Need to handle miu_i
    if len(stack) > 6:
        calls.append(state["pc"])
        for call_pc in calls:
            if call_pc not in calls_affect_state:
                calls_affect_state[call_pc] = False
        state.pc += 1
        outgas = stack.pop()
        recipient = stack.pop()
        transfer_amount = stack.pop()
        start_data_input = stack.pop()
        size_data_input = stack.pop()
        start_data_output = stack.pop()
        size_data_ouput = stack.pop()
        # in the paper, it is shaky when the size of data output is
        # min of stack[6] and the | o |

        if isReal(transfer_amount):
            if transfer_amount == 0:
                stack.push(1)   # x = 0
                return

        # Let us ignore the call depth
        balance_ia = state["balance"]["Ia"]
        is_enough_fund = (transfer_amount <= balance_ia)
        solver.push()
        solver.add(is_enough_fund)

        if check_sat(solver) == unsat:
            # this means not enough fund, thus the execution will result in exception
            solver.pop()
            stack.push(0)   # x = 0
        else:
            # the execution is possibly okay
            stack.push(1)   # x = 1
            solver.pop()
            solver.add(is_enough_fund)
            path_conditions_and_vars["path_condition"].append(is_enough_fund)
            last_idx = len(path_conditions_and_vars["path_condition"]) - 1
            analysis["time_dependency_bug"][last_idx] = state["pc"] - 1
            new_balance_ia = (balance_ia - transfer_amount)
            state["balance"]["Ia"] = new_balance_ia
            address_is = path_conditions_and_vars["Is"]
            address_is = (address_is & CONSTANT_ONES_159)
            boolean_expression = (recipient != address_is)
            solver.push()
            solver.add(boolean_expression)
            if check_sat(solver) == unsat:
                solver.pop()
                new_balance_is = (
                    state["balance"]["Is"] + transfer_amount)
                state["balance"]["Is"] = new_balance_is
            else:
                solver.pop()
                if isReal(recipient):
                    new_address_name = "concrete_address_" + str(recipient)
                else:
                    new_address_name = gen.gen_arbitrary_address_var()
                old_balance_name = gen.gen_arbitrary_var()
                old_balance = BitVec(old_balance_name, 256)
                path_conditions_and_vars[old_balance_name] = old_balance
                constraint = (old_balance >= 0)
                solver.add(constraint)
                path_conditions_and_vars["path_condition"].append(constraint)
                new_balance = (old_balance + transfer_amount)
                state["balance"][new_address_name] = new_balance
    else:
        raise ValueError('STACK underflow')


def OP_CALLCODE():
    # TODO: Need to handle miu_i
    if len(stack) > 6:
        calls.append(state["pc"])
        for call_pc in calls:
            if call_pc not in calls_affect_state:
                calls_affect_state[call_pc] = False
        state.pc += 1
        outgas = stack.pop()
        recipient = stack.pop()  # this is not used as recipient
        if global_params.USE_GLOBAL_STORAGE:
            if isReal(recipient):
                recipient = hex(recipient)
                if recipient[-1] == "L":
                    recipient = recipient[:-1]
                recipients.add(recipient)
            else:
                recipients.add(None)

        transfer_amount = stack.pop()
        start_data_input = stack.pop()
        size_data_input = stack.pop()
        start_data_output = stack.pop()
        size_data_ouput = stack.pop()
        # in the paper, it is shaky when the size of data output is
        # min of stack[6] and the | o |

        if isReal(transfer_amount):
            if transfer_amount == 0:
                stack.push(1)   # x = 0
                return

        # Let us ignore the call depth
        balance_ia = state["balance"]["Ia"]
        is_enough_fund = (transfer_amount <= balance_ia)
        solver.push()
        solver.add(is_enough_fund)

        if check_sat(solver) == unsat:
            # this means not enough fund, thus the execution will result in exception
            solver.pop()
            stack.push(0)   # x = 0
        else:
            # the execution is possibly okay
            stack.push(1)   # x = 1
            solver.pop()
            solver.add(is_enough_fund)
            path_conditions_and_vars["path_condition"].append(is_enough_fund)
            last_idx = len(path_conditions_and_vars["path_condition"]) - 1
            analysis["time_dependency_bug"][last_idx] = state["pc"] - 1
    else:
        raise ValueError('STACK underflow')


def OP_STATICCALL():
    return OP_DELEGATECALL()


def OP_DELEGATECALL():
    if len(stack) > 5:
        state["pc"] += 1
        stack.pop()
        recipient = stack.pop()
        if global_params.USE_GLOBAL_STORAGE:
            if isReal(recipient):
                recipient = hex(recipient)
                if recipient[-1] == "L":
                    recipient = recipient[:-1]
                recipients.add(recipient)
            else:
                recipients.add(None)

        stack.pop()
        stack.pop()
        stack.pop()
        stack.pop()
        new_var_name = gen.gen_arbitrary_var()
        new_var = BitVec(new_var_name, 256)
        stack.push(new_var)
    else:
        raise ValueError('STACK underflow')


def OP_RETURN():
    return OP_REVERT()


def OP_REVERT():
    # TODO: Need to handle miu_i
    if len(stack) > 1:
        revertible_overflow_pcs.update(overflow_pcs)
        state.pc += 1
        stack.pop()
        stack.pop()
        # TODO
        pass
    else:
        raise ValueError('STACK underflow')


def OP_SUICIDE():
    state.pc += 1
    recipient = stack.pop()
    transfer_amount = state["balance"]["Ia"]
    state["balance"]["Ia"] = 0
    if isReal(recipient):
        new_address_name = "concrete_address_" + str(recipient)
    else:
        new_address_name = gen.gen_arbitrary_address_var()
    old_balance_name = gen.gen_arbitrary_var()
    old_balance = BitVec(old_balance_name, 256)
    path_conditions_and_vars[old_balance_name] = old_balance
    constraint = (old_balance >= 0)
    solver.add(constraint)
    path_conditions_and_vars["path_condition"].append(constraint)
    new_balance = (old_balance + transfer_amount)
    state["balance"][new_address_name] = new_balance
    # TODO
    return


def OP_UNKNOWN():
    log.debug("UNKNOWN INSTRUCTION: " + opcode)
    if global_params.UNIT_TEST == 2 or global_params.UNIT_TEST == 3:
        log.critical("Unknown instruction: %s" % opcode)
        exit(UNKNOWN_INSTRUCTION)
    raise Exception('UNKNOWN INSTRUCTION: ' + opcode)
