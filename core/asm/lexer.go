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

package asm

import (
	"fmt"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"
)

// stateFn is used through the lifetime of the
// lexer to parse the different values at the
// current state.在句法分析器的生命周期中使用stateFn来解析当前状态下的不同值。
type stateFn func(*lexer) stateFn

// token is emitted when the lexer has discovered
// a new parsable token. These are delivered over
// the tokens channels of the lexer当词法分析器发现新的可解析令牌时会发出令牌。 这些是通过词法分析器的令牌通道传递的
type token struct {
	typ    tokenType
	lineno int
	text   string
}

// tokenType are the different types the lexer
// is able to parse and return. tokenType是词法分析器能够解析和返回的不同类型。
type tokenType int

const (
	eof              tokenType = iota // end of file
	lineStart                         // emitted when a line starts线开始时发出
	lineEnd                           // emitted when a line ends
	invalidStatement                  // any invalid statement任何无效的陈述
	element                           // any element during element parsing元素解析期间的任何元素
	label                             // label is emitted when a label is found找到标签时会发出标签
	labelDef                          // label definition is emitted when a new label is found找到新标签时会发出标签定义
	number                            // number is emitted when a number is found找到数字时会发出数字
	stringValue                       // stringValue is emitted when a string has been found找到字符串时会发出stringValue

	Numbers            = "1234567890"                                           // characters representing any decimal number
	HexadecimalNumbers = Numbers + "aAbBcCdDeEfF"                               // characters representing any hexadecimal
	Alpha              = "abcdefghijklmnopqrstuwvxyzABCDEFGHIJKLMNOPQRSTUWVXYZ" // characters representing alphanumeric
)

// String implements stringer
func (it tokenType) String() string {
	if int(it) > len(stringtokenTypes) {
		return "invalid"
	}
	return stringtokenTypes[it]
}

var stringtokenTypes = []string{
	eof:              "EOF",
	invalidStatement: "invalid statement",
	element:          "element",
	lineEnd:          "end of line",
	lineStart:        "new line",
	label:            "label",
	labelDef:         "label definition",
	number:           "number",
	stringValue:      "string",
}

// lexer is the basic construct for parsing
// source code and turning them in to tokens.
// Tokens are interpreted by the compiler. lexer是解析源代码并将其转换为tokens的基本构造.Tokens由编译器解释。
type lexer struct {
	input string // input contains the source code of the program input包含程序的源代码

	tokens chan token // tokens is used to deliver tokens to the listener令牌用于将令牌传递给听众
	state  stateFn    // the current state function当前的状态函数

	lineno            int // current line number in the source file源文件中的当前行号
	start, pos, width int // positions for lexing and returning valuelexing和return value的位置

	debug bool // flag for triggering debug output用于触发调试输出的标志
}

// lex lexes the program by name with the given source. It returns a
// channel on which the tokens are delivered. lex使用给定的源名称缩放程序。 它返回一个传递令牌的通道。
func Lex(name string, source []byte, debug bool) <-chan token {
	ch := make(chan token)
	l := &lexer{
		input:  string(source),
		tokens: ch,
		state:  lexLine,
		debug:  debug,
	}
	go func() {
		l.emit(lineStart)
		for l.state != nil {
			l.state = l.state(l)
		}
		l.emit(eof)
		close(l.tokens)
	}()

	return ch
}

// next returns the next rune in the program's source.next返回程序源代码中的下一个符文。
func (l *lexer) next() (rune rune) {
	if l.pos >= len(l.input) {
		l.width = 0
		return 0
	}
	rune, l.width = utf8.DecodeRuneInString(l.input[l.pos:])
	l.pos += l.width
	return rune
}

// backup backsup the last parsed element (multi-character)备份备份最后解析的元素（多字符）
func (l *lexer) backup() {
	l.pos -= l.width
}

// peek returns the next rune but does not advance the seeker peek返回下一个符文，但没有推进寻求者
func (l *lexer) peek() rune {
	r := l.next()
	l.backup()
	return r
}

// ignore advances the seeker and ignores the value忽视推进者并忽略价值
func (l *lexer) ignore() {
	l.start = l.pos
}

// Accepts checks whether the given input matches the next rune接受检查给定输入是否与下一个符文匹配
func (l *lexer) accept(valid string) bool {
	if strings.ContainsRune(valid, l.next()) {
		return true
	}

	l.backup()

	return false
}

// acceptRun will continue to advance the seeker until valid
// can no longer be met.
func (l *lexer) acceptRun(valid string) {
	for strings.ContainsRune(valid, l.next()) {
	}
	l.backup()
}

// acceptRunUntil is the inverse of acceptRun and will continue
// to advance the seeker until the rune has been found.acceptRunUntil是acceptRun的反转，并将继续推进搜索者，直到找到符文。
func (l *lexer) acceptRunUntil(until rune) bool {
	// Continues running until a rune is found继续跑，直到找到符文
	for i := l.next(); !strings.ContainsRune(string(until), i); i = l.next() {
		if i == 0 {
			return false
		}
	}

	return true
}

// blob returns the current value
func (l *lexer) blob() string {
	return l.input[l.start:l.pos]
}

// Emits a new token on to token channel for processing将新令牌发送到令牌通道以进行处理
func (l *lexer) emit(t tokenType) {
	token := token{t, l.lineno, l.blob()}

	if l.debug {
		fmt.Fprintf(os.Stderr, "%04d: (%-20v) %s\n", token.lineno, token.typ, token.text)
	}

	l.tokens <- token
	l.start = l.pos
}

// lexLine is state function for lexing lines  lexLine是lexing线的状态函数
func lexLine(l *lexer) stateFn {
	for {
		switch r := l.next(); {
		case r == '\n':
			l.emit(lineEnd)
			l.ignore()
			l.lineno++

			l.emit(lineStart)
		case r == ';' && l.peek() == ';':
			return lexComment
		case isSpace(r):
			l.ignore()
		case isLetter(r) || r == '_':
			return lexElement
		case isNumber(r):
			return lexNumber
		case r == '@':
			l.ignore()
			return lexLabel
		case r == '"':
			return lexInsideString
		default:
			return nil
		}
	}
}

// lexComment parses the current position until the end
// of the line and discards the text.lexComment解析当前位置直到行尾并丢弃文本。
func lexComment(l *lexer) stateFn {
	l.acceptRunUntil('\n')
	l.ignore()

	return lexLine
}

// lexLabel parses the current label, emits and returns
// the lex text state function to advance the parsing
// process.
func lexLabel(l *lexer) stateFn {
	l.acceptRun(Alpha + "_")

	l.emit(label)

	return lexLine
}

// lexInsideString lexes the inside of a string until
// the state function finds the closing quote.
// It returns the lex text state function.
func lexInsideString(l *lexer) stateFn {
	if l.acceptRunUntil('"') {
		l.emit(stringValue)
	}

	return lexLine
}

func lexNumber(l *lexer) stateFn {
	acceptance := Numbers
	if l.accept("0") || l.accept("xX") {
		acceptance = HexadecimalNumbers
	}
	l.acceptRun(acceptance)

	l.emit(number)

	return lexLine
}

func lexElement(l *lexer) stateFn {
	l.acceptRun(Alpha + "_" + Numbers)

	if l.peek() == ':' {
		l.emit(labelDef)

		l.accept(":")
		l.ignore()
	} else {
		l.emit(element)
	}
	return lexLine
}

func isLetter(t rune) bool {
	return unicode.IsLetter(t)
}

func isSpace(t rune) bool {
	return unicode.IsSpace(t)
}

func isNumber(t rune) bool {
	return unicode.IsNumber(t)
}
