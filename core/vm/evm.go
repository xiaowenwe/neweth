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
	"math/big"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// emptyCodeHash由create使用，以确保不会部署已部署的合同地址（在帐户抽象后相关）。
// emptyCodeHash is used by create to ensure deployment is disallowed to already
// deployed contract addresses (relevant after the account abstraction).
var emptyCodeHash = crypto.Keccak256Hash(nil)

type (
	// CanTransferFunc is the signature of a transfer guard function CanTransferFunc是传输保护功能的签名
	CanTransferFunc func(StateDB, common.Address, *big.Int) bool
	// TransferFunc is the signature of a transfer function TransferFunc是传递函数的签名
	TransferFunc func(StateDB, common.Address, common.Address, *big.Int)
	// GetHashFunc returns the nth block hash in the blockchain
	// and is used by the BLOCKHASH EVM op code.GetHashFunc返回区块链中的第n个块哈希，并由BLOCKHASH EVM操作码使用。
	GetHashFunc func(uint64) common.Hash
)

//EVM中执行合约(指令)的函数是run()
// run runs the given contract and takes care of running precompiles with a fallback to the byte code interpreter.
func run(evm *EVM, contract *Contract, input []byte, readOnly bool) ([]byte, error) {
	//可见如果待执行的Contract对象恰好属于一组预编译的合约集合-此时以指令地址CodeAddr为匹配项-那么它可以直接运行；
	// 没有经过预编译的Contract，才会由Interpreter解释执行。
	// 这里的"预编译"，可理解为不需要编译(解释)指令(Code)。预编译的合约，其逻辑全部固定且已知，所以执行中不再需要Code，仅需Input即可。
	if contract.CodeAddr != nil {
		precompiles := PrecompiledContractsHomestead
		if evm.ChainConfig().IsByzantium(evm.BlockNumber) {
			precompiles = PrecompiledContractsByzantium
		}
		if p := precompiles[*contract.CodeAddr]; p != nil { //在代码实现中，预编译合约只需实现两个方法Required()和Run()即可，这两方法仅需一个入参input
			return RunPrecompiledContract(p, input, contract)
		}
	}
	for _, interpreter := range evm.interpreters {
		if interpreter.CanRun(contract.Code) {
			if evm.interpreter != interpreter {
				// Ensure that the interpreter pointer is set back
				// to its current value upon return.//确保在返回时将解释器指针设置回其当前值。
				defer func(i Interpreter) {
					evm.interpreter = i
				}(evm.interpreter)
				evm.interpreter = interpreter
			}
			return interpreter.Run(contract, input, readOnly) //解释器Interpreter用来执行(非预编译的)合约指令
		}
	}
	return nil, ErrNoCompatibleInterpreter
}

// 上下文为EVM提供辅助信息。 一旦提供，不应该修改。
// Context provides the EVM with auxiliary information. Once provided
// it shouldn't be modified.
type Context struct {
	// CanTransfer returns whether the account contains
	// sufficient ether to transfer the value函数返回账户是否有足够的ether用来转账
	CanTransfer CanTransferFunc
	// Transfer transfers ether from one account to the other
	Transfer TransferFunc
	// GetHash returns the hash corresponding to n GetHash用来返回入参n对应的hash值
	GetHash GetHashFunc

	// Message information
	Origin   common.Address // Provides information for ORIGIN 用来提供Origin的信息 sender的地址
	GasPrice *big.Int       // Provides information for GASPRICE 用来提供GasPrice信息

	// Block information
	Coinbase    common.Address // Provides information for COINBASE
	GasLimit    uint64         // Provides information for GASLIMIT
	BlockNumber *big.Int       // Provides information for NUMBER
	Time        *big.Int       // Provides information for TIME
	Difficulty  *big.Int       // Provides information for DIFFICULTY
}

// EVM is the Ethereum Virtual Machine base object and provides
// the necessary tools to run a contract on the given state with
// the provided context. It should be noted that any error
// generated through any of the calls should be considered a
// revert-state-and-consume-all-gas operation, no checks on
// specific errors should ever be performed. The interpreter makes
// sure that any errors generated are to be considered faulty code.
////// EVM是以太坊虚拟机基础对象，并提供必要的工具，以使用提供的上下文运行给定状态的合约。
//// 应该指出的是，任何调用产生的任何错误都应该被认为是一种回滚修改状态和消耗所有GAS操作，
//// 不应该执行对具体错误的检查。 解释器确保生成的任何错误都被认为是错误的代码。
// The EVM should never be reused and is not thread safe.
type EVM struct {
	// Context provides auxiliary blockchain related information
	Context //携带了Transaction的信息(GasPrice, GasLimit)，Block的信息(Number, Difficulty)，以及转帐函数等
	// StateDB gives access to the underlying state
	StateDB StateDB //tateDB 接口是针对state.StateDB 结构体设计的本地行为接口，可为EVM提供statedb的相关操作
	// Depth is the current call stack// 当前的调用堆栈
	depth int

	// chainConfig contains information about the current chain
	chainConfig *params.ChainConfig // 包含了当前的区块链的信息
	// chain rules contains the chain rules for the current epoch
	chainRules params.Rules //链规则包含当前时期的链规则
	// virtual machine configuration options used to initialise the
	// evm.//用于初始化evm的虚拟机配置选项。
	vmConfig Config
	// global (to this context) ethereum virtual machine
	// used throughout the execution of the tx.//全局（在此上下文中）在整个tx执行过程中使用的以太坊虚拟机。
	interpreters []Interpreter // Interpreter结构体作为解释器，用来解释执行EVM中合约(Contract)的指令(Code)。
	interpreter  Interpreter
	// abort is used to abort the EVM calling operations
	// NOTE: must be set atomically//中止用于中止EVM调用操作
	//	//注意：必须以原子方式设置
	abort int32
	// callGasTemp holds the gas available for the current call. This is needed because the
	// available gas is calculated in gasCall* according to the 63/64 rule and later
	// applied in opCall*.// callGasTemp保存当前通话可用的gas。 这是必要的，因为可用气体是根据63/64规则在gasCall *中计算的，稍后在opCall *中应用。
	callGasTemp uint64
}

// NewEVM重新构建新的EVM。 返回的EVM不是线程安全的，应该只能使用*一次*。
// NewEVM returns a new EVM. The returned EVM is not thread safe and should
// only ever be used *once*.
func NewEVM(ctx Context, statedb StateDB, chainConfig *params.ChainConfig, vmConfig Config) *EVM {
	evm := &EVM{
		Context:      ctx,
		StateDB:      statedb,
		vmConfig:     vmConfig,
		chainConfig:  chainConfig,
		chainRules:   chainConfig.Rules(ctx.BlockNumber),
		interpreters: make([]Interpreter, 0, 1),
	}

	if chainConfig.IsEWASM(ctx.BlockNumber) {
		// to be implemented by EVM-C and Wagon PRs.
		// if vmConfig.EWASMInterpreter != "" {
		//  extIntOpts := strings.Split(vmConfig.EWASMInterpreter, ":")
		//  path := extIntOpts[0]
		//  options := []string{}
		//  if len(extIntOpts) > 1 {
		//    options = extIntOpts[1..]
		//  }
		//  evm.interpreters = append(evm.interpreters, NewEVMVCInterpreter(evm, vmConfig, options))
		// } else {
		// 	evm.interpreters = append(evm.interpreters, NewEWASMInterpreter(evm, vmConfig))
		// }
		panic("No supported ewasm interpreter yet.")
	}
	// EVM-C将使用vmConfig.EVMInterpreter，此处不会检查它，因为我们总是希望将内置EVM作为故障转移选项。
	// vmConfig.EVMInterpreter will be used by EVM-C, it won't be checked here
	// as we always want to have the built-in EVM as the failover option.
	evm.interpreters = append(evm.interpreters, NewEVMInterpreter(evm, vmConfig))
	evm.interpreter = evm.interpreters[0]

	return evm
}

//取消任何正在运行的EVM操作。 这可以同时调用，并且多次调用是安全的。
// Cancel cancels any running EVM operation. This may be called concurrently and
// it's safe to be called multiple times.
func (evm *EVM) Cancel() {
	atomic.StoreInt32(&evm.abort, 1)
}

//Call方法, 无论我们转账或者是执行合约代码都会调用到这里， 同时合约里面的call指令也会执行到这里。
// Interpreter returns the current interpreter
func (evm *EVM) Interpreter() Interpreter {
	return evm.interpreter
}

//Call方法, 无论我们转账或者是执行合约代码都会调用到这里， 同时合约里面的call指令也会执行到这里。
// Call executes the contract associated with the addr with the given input as
// parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
// Call 执行与给定的input作为参数与addr相关联的合约。
// 它还处理所需的任何必要的转账操作，并采取必要的步骤来创建帐户
// 并在任意错误的情况下回滚所做的操作。
func (evm *EVM) Call(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	//1检查交易
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}
	//  调用深度最多1024
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// 查看我们的账户是否有足够的金钱。
	// Fail if we're trying to transfer more than the available balance
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}

	var (
		to       = AccountRef(addr)
		snapshot = evm.StateDB.Snapshot()
	)
	if !evm.StateDB.Exist(addr) { // 查看指定地址是否存在
		// 如果地址不存在，查看是否是 native go的合约， native go的合约在
		// contracts.go 文件里面
		precompiles := PrecompiledContractsHomestead
		if evm.ChainConfig().IsByzantium(evm.BlockNumber) {
			precompiles = PrecompiledContractsByzantium
		}
		if precompiles[addr] == nil && evm.ChainConfig().IsEIP158(evm.BlockNumber) && value.Sign() == 0 {
			// Calling a non existing account, don't do anything, but ping the tracer调用一个不存在的帐户，不要做任何事情，但ping该跟踪器
			if evm.vmConfig.Debug && evm.depth == 0 {
				evm.vmConfig.Tracer.CaptureStart(caller.Address(), addr, false, input, gas, value)
				evm.vmConfig.Tracer.CaptureEnd(ret, 0, 0, nil)
			} // 如果不是指定的合约地址， 并且value的值为0那么返回正常，而且这次调用没有消耗Gas
			return nil, gas, nil
		} // 负责在本地状态创建addr
		evm.StateDB.CreateAccount(addr)
	} // 2执行转账
	evm.Transfer(evm.StateDB, caller.Address(), to.Address(), value)
	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	//3创建一个Contract对象，并初始化其成员变量caller, self(addr), value和gas
	contract := NewContract(caller, to, value, gas)
	//4赋值Contract对象的Code, CodeHash, CodeAddr成员变量
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))
	//即使帐户没有代码，我们也需要继续，因为它可能是预编译
	// Even if the account has no code, we need to continue because it might be a precompile
	start := time.Now()

	// Capture the tracer start/end events in debug mode以调试模式捕获跟踪器开始/结束事件
	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureStart(caller.Address(), addr, false, input, gas, value)

		defer func() { // Lazy evaluation of the parameters//懒加载的参数评估
			evm.vmConfig.Tracer.CaptureEnd(ret, gas-contract.Gas, time.Since(start), err)
		}()
	} //调用run()函数执行该合约的指令，最后Call()函数返回
	ret, err = run(evm, contract, input, false)
	//当EVM返回错误或设置上述创建代码时，我们恢复快照并消耗剩余的气体。 另外，当我们在家园时，这也代表了代码存储瓦斯错误。
	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			// 如果是由revert指令触发的错误，因为ICO一般设置了人数限制或者资金限制
			// 在大家抢购的时候很可能会触发这些限制条件，导致被抽走不少钱。这个时候
			// 又不能设置比较低的GasPrice和GasLimit。因为要速度快。
			// 那么不会使用剩下的全部Gas，而是只会使用代码执行的Gas
			// 不然会被抽走 GasLimit *GasPrice的钱，那可不少。
			contract.UseGas(contract.Gas)
		}
	}
	return ret, contract.Gas, err
}

//剩下的三个函数 CallCode, DelegateCall, 和 StaticCall，这三个函数不能由外部调用，只能由Opcode触发。
// CallCode executes the contract associated with the addr with the given input
// as parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
//// CallCode使用给定输入作为参数执行与addr关联的契约。 它还处理所需的任何必要的值传输，并采取必要的步骤来创建帐户并在执行错误或值传输失败时撤消状态。
// CallCode differs from Call in the sense that it executes the given address'
// code with the caller as context./ CallCode与Call不同的地方在于它使用caller的context来执行给定地址的代码。
func (evm *EVM) CallCode(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}
	//如果我们试图在通话深度限制以上执行，则会失败
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	} //如果我们尝试传输的可用余额超过了，则失败
	// Fail if we're trying to transfer more than the available balance
	if !evm.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}

	var (
		snapshot = evm.StateDB.Snapshot()
		to       = AccountRef(caller.Address()) //这里是最不同的地方 to的地址被修改为caller的地址了 而且没有转账的行为
	) //初始化一个新的契约并设置E将使用的代码该契约是一个仅限于此执行上下文的作用域解释。
	// initialise a new contract and set the code that is to be used by the
	// EVM. The contract is a scoped environment for this execution context
	// only.
	contract := NewContract(caller, to, value, gas)
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	ret, err = run(evm, contract, input, false)
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	return ret, contract.Gas, err
}

// DelegateCall 和 CallCode不同的地方在于 caller被设置为 caller的caller
// DelegateCall executes the contract associated with the addr with the given input
// as parameters. It reverses the state in case of an execution error.
//
// DelegateCall differs from CallCode in the sense that it executes the given address'
// code with the caller as context and the caller is set to the caller of the caller.
// DelegateCall以给定输入作为参数执行与addr关联的合同。 它在执行错误的情况下反转状态。
// DelegateCall与CallCode的不同之处在于，它以呼叫者作为上下文执行给定地址的代码，并将呼叫者设置为呼叫者的调用者。
func (evm *EVM) DelegateCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}

	var (
		snapshot = evm.StateDB.Snapshot()
		to       = AccountRef(caller.Address())
	)
	// 标识为AsDelete()
	// Initialise a new contract and make initialise the delegate values//初始化一个新的合约并初始化委托值
	contract := NewContract(caller, to, nil, gas).AsDelegate()
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	ret, err = run(evm, contract, input, false)
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	return ret, contract.Gas, err
}

// StaticCall执行与给定输入的addr相关联的合同作为参数，同时禁止在调用期间对状态进行任何修改。
//试图执行此类修改的操作码将导致异常，而不是执行修改。
// StaticCall executes the contract associated with the addr with the given input
// as parameters while disallowing any modifications to the state during the call.
// Opcodes that attempt to perform such modifications will result in exceptions
// instead of performing the modifications.
// StaticCall不允许执行任何修改状态的操作，
func (evm *EVM) StaticCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	} //如果我们试图在通话深度限制以上执行，则会失败
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}

	var (
		to       = AccountRef(addr)
		snapshot = evm.StateDB.Snapshot()
	) //初始化一个新的合约并设置EVM使用的代码。 该合同仅限于此执行上下文的作用域环境。
	// Initialise a new contract and set the code that is to be used by the
	// EVM. The contract is a scoped environment for this execution context
	// only.
	contract := NewContract(caller, to, new(big.Int), gas)
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))
	//我们在这里做一个零的AddBalance，只是为了触发触摸。
	//这在Mainnet上无关紧要，在拜占庭时，所有空箱都已消失，但在其他网络，测试和潜在的未来场景中，这是正确的事情和重要事项
	// We do an AddBalance of zero here, just in order to trigger a touch.
	// This doesn't matter on Mainnet, where all empties are gone at the time of Byzantium,
	// but is the correct thing to do and matters on other networks, in tests, and potential
	// future scenarios
	evm.StateDB.AddBalance(addr, bigZero)
	//当EVM返回错误或设置上述创建代码时，我们恢复快照并消耗剩余的气体。 另外，当我们在Homestead时，这也代表了代码存储瓦斯错误。
	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in Homestead this also counts for code storage gas errors.
	ret, err = run(evm, contract, input, true)
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	return ret, contract.Gas, err
}

type codeAndHash struct {
	code []byte
	hash common.Hash
}

func (c *codeAndHash) Hash() common.Hash {
	if c.hash == (common.Hash{}) {
		c.hash = crypto.Keccak256Hash(c.code)
	}
	return c.hash
}

//合约创建 Create 会创建一个新的合约。
// create creates a new contract using code as deployment code.
func (evm *EVM) create(caller ContractRef, codeAndHash *codeAndHash, gas uint64, value *big.Int, address common.Address) ([]byte, common.Address, uint64, error) {
	// Depth check execution. Fail if we're trying to execute above the
	// limit.//深度检查执行。 如果我们试图超出限制执行失败。
	if evm.depth > int(params.CallCreateDepth) {
		return nil, common.Address{}, gas, ErrDepth
	}
	if !evm.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, common.Address{}, gas, ErrInsufficientBalance
	}
	nonce := evm.StateDB.GetNonce(caller.Address())
	evm.StateDB.SetNonce(caller.Address(), nonce+1)
	// 确保特定的地址没有合约存在
	// Ensure there's no existing contract already at the designated address
	contractHash := evm.StateDB.GetCodeHash(address)
	if evm.StateDB.GetNonce(address) != 0 || (contractHash != (common.Hash{}) && contractHash != emptyCodeHash) {
		return nil, common.Address{}, 0, ErrContractAddressCollision
	}
	// Create a new account on the state
	snapshot := evm.StateDB.Snapshot() //创建一个StateDB的快照，以便回滚
	evm.StateDB.CreateAccount(address) //创建账户
	if evm.ChainConfig().IsEIP158(evm.BlockNumber) {
		evm.StateDB.SetNonce(address, 1) //设置nonce
	} //3执行交易
	evm.Transfer(evm.StateDB, caller.Address(), address, value)
	//初始化一个新的契约并设置E将使用的代码该契约是一个仅限于此执行上下文的作用域解释。
	// initialise a new contract and set the code that is to be used by the
	// EVM. The contract is a scoped environment for this execution context
	// only.
	//4创建一个Contract对象，并初始化其成员变量caller, self(addr), value和gas
	contract := NewContract(caller, AccountRef(address), value, gas)
	//)5赋值Contract对象的Code, CodeHash, CodeAddr成员变量//db中尚无与该地址相关的Code信息，所以会将类型为[]byte的入参code，赋值予Contract对象的Code成员
	contract.SetCodeOptionalHash(&address, codeAndHash)

	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, address, gas, nil
	}

	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureStart(caller.Address(), address, true, codeAndHash.code, gas, value)
	}
	start := time.Now()
	//6调用run()函数执行该合约的指令
	ret, err := run(evm, contract, nil, false)
	// 检查初始化生成的代码的长度不超过限制
	// check whether the max code size has been exceeded
	maxCodeSizeExceeded := evm.ChainConfig().IsEIP158(evm.BlockNumber) && len(ret) > params.MaxCodeSize
	// if the contract creation ran successfully and no errors were returned
	// calculate the gas required to store the code. If the code could not
	// be stored due to not enough gas set an error and let it be handled
	// by the error checking condition below.
	//如果合同创建成功并且没有错误返回，则计算存储代码所需的GAS。 如果由于没有足够的GAS而导致代码不能被存储设置错误，并通过下面的错误检查条件来处理。
	if err == nil && !maxCodeSizeExceeded {
		createDataGas := uint64(len(ret)) * params.CreateDataGas
		if contract.UseGas(createDataGas) {
			evm.StateDB.SetCode(address, ret)
		} else {
			err = ErrCodeStoreOutOfGas
		}
	}
	//当EVM返回错误或设置上述创建代码时，我们恢复快照并消耗剩余的气体。 另外，当我们在家园时，这也代表了代码存储瓦斯错误。
	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if maxCodeSizeExceeded || (err != nil && (evm.ChainConfig().IsHomestead(evm.BlockNumber) || err != ErrCodeStoreOutOfGas)) {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	} //如果在err仍然为空时合同代码大小超过最大值，则分配err。
	// Assign err if contract code size exceeds the max while the err is still empty.
	if maxCodeSizeExceeded && err == nil {
		err = errMaxCodeSizeExceeded
	}
	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureEnd(ret, gas-contract.Gas, time.Since(start), err)
	} //7将本次执行合约的返回结果，作为contractAddr所对应账户(stateObject对象)的Code储存起来，以备下次调用。
	return ret, address, contract.Gas, err

}

// Create使用代码作为部署代码创建新合同。
// Create creates a new contract using code as deployment code.
func (evm *EVM) Create(caller ContractRef, code []byte, gas uint64, value *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	contractAddr = crypto.CreateAddress(caller.Address(), evm.StateDB.GetNonce(caller.Address()))
	return evm.create(caller, &codeAndHash{code: code}, gas, value, contractAddr)
}

// Create2使用代码作为部署代码创建新合同。
// Create2与Create之间的区别是Create2使用sha3（0xff ++ msg.sender ++ salt ++ sha3（init_code））[12：]
//而不是通常的sender-and-nonce-hash作为初始化合同的地址。
// Create2 creates a new contract using code as deployment code.
//
// The different between Create2 with Create is Create2 uses sha3(0xff ++ msg.sender ++ salt ++ sha3(init_code))[12:]
// instead of the usual sender-and-nonce-hash as the address where the contract is initialized at.
func (evm *EVM) Create2(caller ContractRef, code []byte, gas uint64, endowment *big.Int, salt *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	codeAndHash := &codeAndHash{code: code}
	contractAddr = crypto.CreateAddress2(caller.Address(), common.BigToHash(salt), codeAndHash.Hash().Bytes())
	return evm.create(caller, codeAndHash, gas, endowment, contractAddr)
}

// ChainConfig返回环境的链配置
// ChainConfig returns the environment's chain configuration
func (evm *EVM) ChainConfig() *params.ChainConfig { return evm.chainConfig }
