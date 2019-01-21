// Copyright 2016 The go-ethereum Authors
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

package core

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
)
// ChainContext支持从交易处理过程中使用的当前区块链中检索标题和共识参数。
// ChainContext supports retrieving headers and consensus parameters from the
// current blockchain to be used during transaction processing.
type ChainContext interface {
	// Engine retrieves the chain's consensus engine.//引擎检索链的共识引擎。
	Engine() consensus.Engine
	// GetHeader返回与它们的哈希对应的哈希。
	// GetHeader returns the hash corresponding to their hash.
	GetHeader(common.Hash, uint64) *types.Header
}
// NewEVMContext创建一个新的上下文以用于EVM。
// NewEVMContext creates a new context for use in the EVM.
func NewEVMContext(msg Message, header *types.Header, chain ChainContext, author *common.Address) vm.Context {
	// If we don't have an explicit author (i.e. not mining), extract from the header
	//如果我们没有明确的作者（即不是挖掘），请从标题中提取
	var beneficiary common.Address
	if author == nil {
		beneficiary, _ = chain.Engine().Author(header) // Ignore error, we're past header validation忽略错误，我们已通过标头验证
	} else {
		beneficiary = *author
	}
	return vm.Context{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     GetHashFn(header, chain),
		Origin:      msg.From(),
		Coinbase:    beneficiary,
		BlockNumber: new(big.Int).Set(header.Number),
		Time:        new(big.Int).Set(header.Time),
		Difficulty:  new(big.Int).Set(header.Difficulty),
		GasLimit:    header.GasLimit,
		GasPrice:    new(big.Int).Set(msg.GasPrice()),
	}
}
// GetHashFn返回一个GetHashFunc，它通过数字来检索头部哈希值
// GetHashFn returns a GetHashFunc which retrieves header hashes by number
func GetHashFn(ref *types.Header, chain ChainContext) func(n uint64) common.Hash {
	var cache map[uint64]common.Hash

	return func(n uint64) common.Hash {
		// If there's no hash cache yet, make one如果还没有哈希缓存，请创建一个
		if cache == nil {
			cache = map[uint64]common.Hash{
				ref.Number.Uint64() - 1: ref.ParentHash,
			}
		}
		// Try to fulfill the request from the cache尝试从缓存中完成请求
		if hash, ok := cache[n]; ok {
			return hash
		}
		// Not cached, iterate the blocks and cache the hashes不缓存，迭代块并缓存哈希
		for header := chain.GetHeader(ref.ParentHash, ref.Number.Uint64()-1); header != nil; header = chain.GetHeader(header.ParentHash, header.Number.Uint64()-1) {
			cache[header.Number.Uint64()-1] = header.ParentHash
			if n == header.Number.Uint64()-1 {
				return header.ParentHash
			}
		}
		return common.Hash{}
	}
}
//可以转账检查地址帐户中是否有足够的资金进行转帐。
//这并没有采取必要的措施来确保传输的有效性。
// CanTransfer checks whether there are enough funds in the address' account to make a transfer.
// This does not take the necessary gas in to account to make the transfer valid.
func CanTransfer(db vm.StateDB, addr common.Address, amount *big.Int) bool {
	return db.GetBalance(addr).Cmp(amount) >= 0
}
//传输从发件人中扣除金额，并使用给定的Db向收件人添加金额
// Transfer subtracts amount from sender and adds amount to recipient using the given Db
func Transfer(db vm.StateDB, sender, recipient common.Address, amount *big.Int) {
	db.SubBalance(sender, amount)
	db.AddBalance(recipient, amount)
}
