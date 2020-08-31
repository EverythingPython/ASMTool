
# ref
> https://github.com/trailofbits/evm-opcodes
> http://solidity.readthedocs.io/en/v0.4.21/assembly.html
> 
# detail

| Instruction             | don't push   | F, H, B or C for Frontier, Homestead, Byzantium or Constantinople  | Explanation                                                     |
|--|--|--|--|
| stop                    | `-` | F | stop execution, identical to return(0,0)                        |
| add(x, y)               |     | F | x + y                                                           |
| sub(x, y)               |     | F | x - y                                                           |
| mul(x, y)               |     | F | x * y                                                           |
| div(x, y)               |     | F | x / y                                                           |
| sdiv(x, y)              |     | F | x / y, for signed numbers in two's complement                   |
| mod(x, y)               |     | F | x % y                                                           |
| smod(x, y)              |     | F | x % y, for signed numbers in two's complement                   |
| exp(x, y)               |     | F | x to the power of y                                             |
| not(x)                  |     | F | ~x, every bit of x is negated                                   |
| lt(x, y)                |     | F | 1 if x < y, 0 otherwise                                         |
| gt(x, y)                |     | F | 1 if x > y, 0 otherwise                                         |
| slt(x, y)               |     | F | 1 if x < y, 0 otherwise, for signed numbers in two's complement |
| sgt(x, y)               |     | F | 1 if x > y, 0 otherwise, for signed numbers in two's complement |
| eq(x, y)                |     | F | 1 if x == y, 0 otherwise                                        |
| iszero(x)               |     | F | 1 if x == 0, 0 otherwise                                        |
| and(x, y)               |     | F | bitwise and of x and y                                          |
| or(x, y)                |     | F | bitwise or of x and y                                           |
| xor(x, y)               |     | F | bitwise xor of x and y                                          |
| byte(n, x)              |     | F | nth byte of x, where the most significant byte is the 0th byte  |
| shl(x, y)               |     | C | logical shift left y by x bits                                  |
| shr(x, y)               |     | C | logical shift right y by x bits                                 |
| sar(x, y)               |     | C | arithmetic shift right y by x bits                              |
| addmod(x, y, m)         |     | F | (x + y) % m with arbitrary precision arithmetics                |
| mulmod(x, y, m)         |     | F | (x * y) % m with arbitrary precision arithmetics                |
| signextend(i, x)        |     | F | sign extend from (i*8+7)th bit counting from least significant  |
| keccak256(p, n)         |     | F | keccak(mem[p...(p+n)))                                          |
| sha3(p, n)              |     | F | keccak(mem[p...(p+n)))                                          |
| jump(label)             | `-` | F | jump to label / code position                                   |
| jumpi(label, cond)      | `-` | F | jump to label if cond is nonzero                                |
| pc                      |     | F | current position in code                                        |
| pop(x)                  | `-` | F | remove the element pushed by x                                  |
| dup1 ... dup16          |     | F | copy ith stack slot to the top (counting from top)              |
| swap1 ... swap16        | `*` | F | swap topmost and ith stack slot below it                        |
| mload(p)                |     | F | mem[p..(p+32))                                                  |
| mstore(p, v)            | `-` | F | mem[p..(p+32)) := v                                             |
| mstore8(p, v)           | `-` | F | mem[p] := v & 0xff (only modifies a single byte)                |
| sload(p)                |     | F | storage[p]                                                      |
| sstore(p, v)            | `-` | F | storage[p] := v                                                 |
| msize                   |     | F | size of memory, i.e. largest accessed memory index              |
| gas                     |     | F | gas still available to execution                                |
| address                 |     | F | address of the current contract / execution context             |
| balance(a)              |     | F | wei balance at address a                                        |
| caller                  |     | F | call sender (excluding ``delegatecall``)                        |
| callvalue               |     | F | wei sent together with the current call                         |
| calldataload(p)         |     | F | call data starting from position p (32 bytes)                   |
| calldatasize            |     | F | size of call data in bytes                                      |
| calldatacopy(t, f, s)   | `-` | F | copy s bytes from calldata at position f to mem at position t   |
| codesize                |     | F | size of the code of the current contract / execution context    |
| codecopy(t, f, s)       | `-` | F | copy s bytes from code at position f to mem at position t       |
| extcodesize(a)          |     | F | size of the code at address a                                   |
| extcodecopy(a, t, f, s) | `-` | F | like codecopy(t, f, s) but take code at address a               |
| returndatasize          |     | B | size of the last returndata                                     |
| returndatacopy(t, f, s) | `-` | B | copy s bytes from returndata at position f to mem at position t |
| create(v, p, s)         |     | F | create new contract with code mem[p..(p+s)) and send v wei      |
|                         |     |   | and return the new address                                      |
| create2(v, n, p, s)     |     | C | create new contract with code mem[p..(p+s)) at address          |
|                         |     |   | keccak256(<address> . n . keccak256(mem[p..(p+s))) and send v   |
|                         |     |   | wei and return the new address                                  |
| call(g, a, v, in,       |     | F | call contract at address a with input mem[in..(in+insize))      |
| insize, out, outsize)   |     |   | providing g gas and v wei and output area                       |
|                         |     |   | mem[out..(out+outsize)) returning 0 on error (eg. out of gas)   |
|                         |     |   | and 1 on success                                                |
| callcode(g, a, v, in,   |     | F | identical to ``call`` but only use the code from a and stay     |
| insize, out, outsize)   |     |   | in the context of the current contract otherwise                |
| delegatecall(g, a, in,  |     | H | identical to ``callcode`` but also keep ``caller``              |
| insize, out, outsize)   |     |   | and ``callvalue``                                               |
| staticcall(g, a, in,    |     | B | identical to ``call(g, a, 0, in, insize, out, outsize)`` but do |
| insize, out, outsize)   |     |   | not allow state modifications                                   |
| return(p, s)            | `-` | F | end execution, return data mem[p..(p+s))                        |
| revert(p, s)            | `-` | B | end execution, revert state changes, return data mem[p..(p+s))  |
| selfdestruct(a)         | `-` | F | end execution, destroy current contract and send funds to a     |
| invalid                 | `-` | F | end execution with invalid instruction                          |
| log0(p, s)              | `-` | F | log without topics and data mem[p..(p+s))                       |
| log1(p, s, t1)          | `-` | F | log with topic t1 and data mem[p..(p+s))                        |
| log2(p, s, t1, t2)      | `-` | F | log with topics t1, t2 and data mem[p..(p+s))                   |
| log3(p, s, t1, t2, t3)  | `-` | F | log with topics t1, t2, t3 and data mem[p..(p+s))               |
| log4(p, s, t1, t2, t3,  | `-` | F | log with topics t1, t2, t3, t4 and data mem[p..(p+s))           |
| t4)                     |     |   |                                                                 |
| origin                  |     | F | transaction sender                                              |
| gasprice                |     | F | gas price of the transaction                                    |
| blockhash(b)            |     | F | hash of block nr b - only for last 256 blocks excluding current |
| coinbase                |     | F | current mining beneficiary                                      |
| timestamp               |     | F | timestamp of the current block in seconds since the epoch       |
| number                  |     | F | current block number                                            |
| difficulty              |     | F | difficulty of the current block                                 |
| gaslimit                |     | F | block gas limit of the current block                            |
