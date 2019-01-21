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
	"math/big"
)

//vm使用了stack.go里面的对象Stack来作为虚拟机的堆栈。memory代表了虚拟机里面使用的内存对象。
// Stack is an object for basic stack operations. Items popped to the stack are
// expected to be changed and modified. stack does not take care of adding newly
// initialised objects.//比较简单，就是用1024个big.Int的定长数组来作为堆栈的存储。
type Stack struct {
	data []*big.Int
}

func newstack() *Stack {
	return &Stack{data: make([]*big.Int, 0, 1024)}
}

// Data returns the underlying big.Int array.
func (st *Stack) Data() []*big.Int {
	return st.data
}

func (st *Stack) push(d *big.Int) { //追加到最末尾
	// NOTE push limit (1024) is checked in baseCheck
	//stackItem := new(big.Int).Set(d)
	//st.data = append(st.data, stackItem)
	st.data = append(st.data, d)
}
func (st *Stack) pushN(ds ...*big.Int) {
	st.data = append(st.data, ds...)
}

func (st *Stack) pop() (ret *big.Int) { //从最末尾取出。
	ret = st.data[len(st.data)-1]
	st.data = st.data[:len(st.data)-1]
	return
}

func (st *Stack) len() int {
	return len(st.data)
}

func (st *Stack) swap(n int) { //交换堆栈顶的元素和离栈顶n距离的元素的值。
	st.data[st.len()-n], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-n]
}

func (st *Stack) dup(pool *intPool, n int) { //dup操作 像复制指定位置的值到堆顶
	st.push(pool.get().Set(st.data[st.len()-n]))
}

func (st *Stack) peek() *big.Int { //peek 操作. 偷看栈顶元素
	return st.data[st.len()-1]
}

// Back returns the n'th item in stack
func (st *Stack) Back(n int) *big.Int { //Back 偷看指定位置的元素
	return st.data[st.len()-n-1]
}

func (st *Stack) require(n int) error { //require 保证堆栈元素的数量要大于等于n.
	if st.len() < n {
		return fmt.Errorf("stack underflow (%d <=> %d)", len(st.data), n)
	}
	return nil
}

// Print dumps the content of the stack
func (st *Stack) Print() {
	fmt.Println("### stack ###")
	if len(st.data) > 0 {
		for i, val := range st.data {
			fmt.Printf("%-3d  %v\n", i, val)
		}
	} else {
		fmt.Println("-- empty --")
	}
	fmt.Println("#############")
}
