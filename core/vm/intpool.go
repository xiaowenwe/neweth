// Copyright 2017 The go-ethereum Authors
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
	"sync"
)

//非常简单. 就是256大小的 big.int的池,用来加速bit.Int的分配
var checkVal = big.NewInt(-42)

const poolLimit = 256

// intPool是一个大整数池
//可以重用于所有big.Int操作。
// intPool is a pool of big integers that
// can be reused for all big.Int operations.
type intPool struct {
	pool *Stack
}

func newIntPool() *intPool {
	return &intPool{pool: newstack()}
}

// get从池中检索一个大的int，如果池为空则分配一个int。
//注意，返回的int的值是任意的，不会归零！
// get retrieves a big int from the pool, allocating one if the pool is empty.
// Note, the returned int's value is arbitrary and will not be zeroed!
func (p *intPool) get() *big.Int {
	if p.pool.len() > 0 {
		return p.pool.pop()
	}
	return new(big.Int)
}

// getZero从池中检索一个大的int，将其设置为零，或者如果池为空，则分配一个新的int。
// getZero retrieves a big int from the pool, setting it to zero or allocating
// a new one if the pool is empty.
func (p *intPool) getZero() *big.Int {
	if p.pool.len() > 0 {
		return p.pool.pop().SetUint64(0)
	}
	return new(big.Int)
}

// put将一个已分配的大型int返回给池，以便以后通过get调用重用。
//注意，保存的值是; 没有把全部输出也没有得到零！
// put returns an allocated big int to the pool to be later reused by get calls.
// Note, the values as saved as is; neither put nor get zeroes the ints out!
func (p *intPool) put(is ...*big.Int) {
	if len(p.pool.data) > poolLimit {
		return
	}
	for _, i := range is {
		// verifyPool is a build flag. Pool verification makes sure the integrity
		// of the integer pool by comparing values to a default value.// verifyPool是一个构建标志。 池验证通过将值与默认值进行比较来确保整数池的完整性。
		if verifyPool {
			i.Set(checkVal)
		}
		p.pool.push(i)
	}
}

// The intPool pool's default capacity intPool池的默认容量
const poolDefaultCap = 25

// intPoolPool manages a pool of intPools.
type intPoolPool struct {
	pools []*intPool
	lock  sync.Mutex
}

var poolOfIntPools = &intPoolPool{
	pools: make([]*intPool, 0, poolDefaultCap),
}

// get is looking for an available pool to return.get正在寻找可用的池来返回。
func (ipp *intPoolPool) get() *intPool {
	ipp.lock.Lock()
	defer ipp.lock.Unlock()

	if len(poolOfIntPools.pools) > 0 {
		ip := ipp.pools[len(ipp.pools)-1]
		ipp.pools = ipp.pools[:len(ipp.pools)-1]
		return ip
	}
	return newIntPool()
}

// put a pool that has been allocated with get.
func (ipp *intPoolPool) put(ip *intPool) {
	ipp.lock.Lock()
	defer ipp.lock.Unlock()

	if len(ipp.pools) < cap(ipp.pools) {
		ipp.pools = append(ipp.pools, ip)
	}
}
