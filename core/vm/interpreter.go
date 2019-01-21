// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"fmt"
	"hash"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/params"
)

// Config are the configuration options for the Interpreter// Config是解释器的配置选项
type Config struct {
	// Debug enabled debugging Interpreter options//调试启用调试解释器选项
	Debug bool
	// Tracer is the op code logger Tracer是操作代码记录器
	Tracer Tracer
	//禁用NoRecursion解释器call，callcode，
	//delegate call并创建。
	// NoRecursion disabled Interpreter call, callcode,
	// delegate call and create.
	NoRecursion bool
	//启用SHA3 / keccak preimages的记录
	// Enable recording of SHA3/keccak preimages
	EnablePreimageRecording bool
	// JumpTable contains the EVM instruction table. This
	// may be left uninitialised and will be set to the default
	// table.	// JumpTable包含EVM指令表。 这可能会保持未初始化状态并将被设置为默认表。
	JumpTable [256]operation

	// Type of the EWASM interpreterEWASM解释器的类型
	EWASMInterpreter string
	// Type of the EVM interpreterEVM解释器的类型
	EVMInterpreter string
}

// Interpreter用于运行基于以太坊的合同，并将利用已传递的证据向外部源查询状态信息。
//解释器将根据传递的配置运行字节码VM或JIT VM。
// Interpreter is used to run Ethereum based contracts and will utilise the
// passed environment to query external sources for state information.
// The Interpreter will run the byte code VM based on the passed
// configuration.
type Interpreter interface {
	// Run loops and evaluates the contract's code with the given input data and returns
	// the return byte-slice and an error if one occurred.运行循环并使用给定的输入数据计算合同的代码，并返回返回的字节切片，如果发生错误则返回错误。
	Run(contract *Contract, input []byte, static bool) ([]byte, error)
	// CanRun tells if the contract, passed as an argument, can be
	// run by the current interpreter. This is meant so that the
	// caller can do something like:CanRun告诉作为参数传递的契约是否可以由当前解释器运行。 这意味着调用者可以执行以下操作：
	//
	// ```golang
	// for _, interpreter := range interpreters {
	//   if interpreter.CanRun(contract.code) {
	//     interpreter.Run(contract.code, input)
	//   }
	// }
	// ```
	CanRun([]byte) bool
}

//keccakState包装sha3.state。 除了通常的哈希方法之外，它还支持Read以从哈希状态获取可变数量的数据。 Read比Sum快，因为它不复制内部状态，但也修改内部状态。
// keccakState wraps sha3.state. In addition to the usual hash methods, it also supports
// Read to get a variable amount of data from the hash state. Read is faster than Sum
// because it doesn't copy the internal state, but also modifies the internal state.
type keccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

// EVMInterpreter represents an EVM interpreter EVMInterpreter表示EVM解释器
type EVMInterpreter struct {
	evm      *EVM
	cfg      Config //Config类型的成员变量，间接持有一个包括256个operation对象在内的数组JumpTable。
	gasTable params.GasTable

	intPool *intPool

	hasher    keccakState // Keccak256 hasher instance shared across opcodesKeccak256 hasher实例共享操作码
	hasherBuf common.Hash // Keccak256 hasher result array shared aross opcodes Keccak256 hasher结果数组共享aross操作码

	readOnly   bool   // Whether to throw on stateful modifications 是否要进行有状态的修改
	returnData []byte // Last CALL's return data for subsequent reuse 最后一个CALL的返回数据，供后续重用
}

// NewEVMInterpreter returns a new instance of the Interpreter.返回解释器的新实例。
func NewEVMInterpreter(evm *EVM, cfg Config) *EVMInterpreter {
	// We use the STOP instruction whether to see
	// the jump table was initialised. If it was not
	// we'll set the default jump table.// 用一个STOP指令测试JumpTable是否已经被初始化了, 如果没有被初始化,那么设置为默认值
	if !cfg.JumpTable[STOP].valid {
		switch {
		case evm.ChainConfig().IsConstantinople(evm.BlockNumber):
			cfg.JumpTable = constantinopleInstructionSet
		case evm.ChainConfig().IsByzantium(evm.BlockNumber):
			cfg.JumpTable = byzantiumInstructionSet
		case evm.ChainConfig().IsHomestead(evm.BlockNumber):
			cfg.JumpTable = homesteadInstructionSet
		default:
			cfg.JumpTable = frontierInstructionSet
		}
	}

	return &EVMInterpreter{
		evm:      evm,
		cfg:      cfg,
		gasTable: evm.ChainConfig().GasTable(evm.BlockNumber),
	}
}

func (in *EVMInterpreter) enforceRestrictions(op OpCode, operation operation, stack *Stack) error {
	if in.evm.chainRules.IsByzantium {
		if in.readOnly {
			// If the interpreter is operating in readonly mode, make sure no
			// state-modifying operation is performed. The 3rd stack item
			// for a call operation is the value. Transferring value from one
			// account to the others means the state is modified and should also
			// return with an error.//如果解释器以只读模式运行，请确保未执行状态修改操作。 调用操作的第3个堆栈项是值。
			// 将值从一个帐户转移到其他帐户意味着状态已修改，并且还应返回错误。
			if operation.writes || (op == CALL && stack.Back(2).BitLen() > 0) {
				return errWriteProtection
			}
		}
	}
	return nil
}

// Run loops and evaluates the contract's code with the given input data and returns
// the return byte-slice and an error if one occurred.
//运行循环并使用给定的输入数据计算合同的代码，并返回返回的字节切片，如果发生错误则返回错误。
// 重要的是要注意，解释器返回的任何错误都应该被视为一个revert-and-consume-all-gas操作，除了errExecutionReverted，这意味着revert-and-keep-gas-left。
// It's important to note that any errors returned by the interpreter should be
// considered a revert-and-consume-all-gas operation except for
// errExecutionReverted which means revert-and-keep-gas-left.
func (in *EVMInterpreter) Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error) {
	if in.intPool == nil {
		in.intPool = poolOfIntPools.get()
		defer func() {
			poolOfIntPools.put(in.intPool)
			in.intPool = nil
		}()
	}

	// Increment the call depth which is restricted to 1024增加调用深度，限制为1024
	in.evm.depth++
	defer func() { in.evm.depth-- }()
	//确保只在我们还没有readOnly的情况下才设置readOnly。
	//这也确保不会为子调用删除readOnly标志。
	// Make sure the readOnly is only set if we aren't in readOnly yet.
	// This makes also sure that the readOnly flag isn't removed for child calls.
	if readOnly && !in.readOnly {
		in.readOnly = true
		defer func() { in.readOnly = false }()
	}
	//重置上一个呼叫的返回数据。 保留旧缓冲区并不重要，因为每次返回的调用都会返回新数据。
	// Reset the previous call's return data. It's unimportant to preserve the old buffer
	// as every returning call will return new data anyway.
	in.returnData = nil

	// Don't bother with the execution if there's no code.如果没有代码，请不要为执行而烦恼。
	if len(contract.Code) == 0 {
		return nil, nil
	}

	var (
		op    OpCode        // current opcode
		mem   = NewMemory() // bound memory
		stack = newstack()  // local stack
		//出于优化原因，我们使用uint64作为程序计数器。
		//理论上可以超过2 ^ 64。 YP定义了PC
		//是uint256 实际上更不可行。
		// For optimisation reason we're using uint64 as the program counter.
		// It's theoretically possible to go above 2^64. The YP defines the PC
		// to be uint256. Practically much less so feasible.
		pc   = uint64(0) // program counter
		cost uint64
		// copies used by tracer示踪剂使用的副本
		pcCopy  uint64 // needed for the deferred Tracer延迟跟踪器所需的
		gasCopy uint64 // for Tracer to log gas remaining before execution跟踪器在执行前记录剩余的气体
		logged  bool   // deferred Tracer should ignore already logged steps延迟Tracer应该忽略已记录的步骤
	)
	contract.Input = input

	// Reclaim the stack as an int pool when the execution stops执行停止时将堆栈回收为int池
	defer func() { in.intPool.put(stack.data...) }()

	if in.cfg.Debug {
		defer func() {
			if err != nil {
				if !logged {
					in.cfg.Tracer.CaptureState(in.evm, pcCopy, op, gasCopy, cost, mem, stack, contract, in.evm.depth, err)
				} else {
					in.cfg.Tracer.CaptureFault(in.evm, pcCopy, op, gasCopy, cost, mem, stack, contract, in.evm.depth, err)
				}
			}
		}()
	}
	// The Interpreter main run loop (contextual). This loop runs until either an
	// explicit STOP, RETURN or SELFDESTRUCT is executed, an error occurred during
	// the execution of one of the operations or until the done flag is set by the
	// parent context.//解释器的主要循环， 直到遇到STOP，RETURN，SELFDESTRUCT指令被执行，或者是遇到任意错误，或者说done 标志被父context设置。
	for atomic.LoadInt32(&in.evm.abort) == 0 {
		if in.cfg.Debug {
			// Capture pre-execution values for tracing.//捕获跟踪的预执行值。
			logged, pcCopy, gasCopy = false, pc, contract.Gas
		}
		//从跳转表中获取操作并验证堆栈以确保有足够的堆栈项目可用于执行操作。
		// Get the operation from the jump table and validate the stack to ensure there are
		// enough stack items available to perform the operation.
		op = contract.GetOp(pc)
		// 拿到下一个需要执行的指令
		operation := in.cfg.JumpTable[op]
		if !operation.valid { //检查指令是否非法
			return nil, fmt.Errorf("invalid opcode 0x%x", int(op))
		}
		if err := operation.validateStack(stack); err != nil { // 检查是否有足够的堆栈空间。 包括入栈和出栈
			return nil, err
		}
		// 这里检查了只读模式下面不能执行writes指令
		// staticCall的情况下会设置为readonly模式
		// If the operation is valid, enforce and write restrictions如果操作有效，则强制执行并写入限制
		if err := in.enforceRestrictions(op, operation, stack); err != nil {
			return nil, err
		}

		var memorySize uint64
		// calculate the new memory size and expand the memory to fit
		// the operation//计算新的内存大小并扩展内存以适应操作
		if operation.memorySize != nil {
			memSize, overflow := bigUint64(operation.memorySize(stack))
			if overflow {
				return nil, errGasUintOverflow
			} //内存以32字节的单词扩展。 气体也用文字计算。
			// memory is expanded in words of 32 bytes. Gas
			// is also calculated in words.
			if memorySize, overflow = math.SafeMul(toWordSize(memSize), 32); overflow {
				return nil, errGasUintOverflow
			}
		} // 计算gas的Cost 并使用，如果不够，就返回OutOfGas错误。
		// consume the gas and return an error if not enough gas is available.
		// cost is explicitly set so that the capture state defer method can get the proper cost
		cost, err = operation.gasCost(in.gasTable, in.evm, contract, stack, mem, memorySize)
		if err != nil || !contract.UseGas(cost) {
			return nil, ErrOutOfGas
		}
		if memorySize > 0 { //扩大内存范围
			mem.Resize(memorySize)
		}

		if in.cfg.Debug {
			in.cfg.Tracer.CaptureState(in.evm, pc, op, gasCopy, cost, mem, stack, contract, in.evm.depth, err)
			logged = true
		}
		// 执行命令
		// execute the operation
		res, err := operation.execute(&pc, in, contract, mem, stack)
		// verifyPool是一个构建标志。 池验证通过将值与默认值进行比较来确保整型池的完整性。
		// verifyPool is a build flag. Pool verification makes sure the integrity
		// of the integer pool by comparing values to a default value.
		if verifyPool {
			verifyIntegerPool(in.intPool)
		} //如果操作清除返回数据（例如返回数据），则将最后一次返回设置为操作结果。
		// if the operation clears the return data (e.g. it has returning data)
		// set the last return to the result of the operation.
		if operation.returns { //如果有返回值，那么就设置返回值。 注意只有最后一个返回有效果。
			in.returnData = res
		}

		switch {
		case err != nil:
			return nil, err
		case operation.reverts:
			return res, errExecutionReverted
		case operation.halts:
			return res, nil
		case !operation.jumps:
			pc++
		}
	}
	return nil, nil
}

// CanRun tells if the contract, passed as an argument, can be
// run by the current interpreter.
func (in *EVMInterpreter) CanRun(code []byte) bool {
	return true
}
