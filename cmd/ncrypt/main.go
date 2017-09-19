// Copyright (C) 2017 Minio Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Ncrypt en/decrypts arbitrary data streams securely.
//
// Without an input file it reads from STDIN and writes to
// STDOUT if no output file is specified.
//
// Usage: ncrypt [FLAGS] [ARGUMENTS...]
//
//    -cipher string   Specify cipher - default: platform depended
//    -d               Decrypt
//    -list            List supported algorithms
//
//
// Examples:
//
// Encrypt file 'myfile.txt':                  ncrypt ~/myfile.txt ~/myfile.txt.enc
// Decrypt 'myfile.txt.enc' and print content: ncrypt -d ~/myfile.txt
// Encrypt file 'myfile.txt' using unix pipes: cat ~/myfile.txt | ncrypt > ~/myfile.txt.enc
package main // import "github.com/minio/sio/cmd/ncrypt"

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"syscall"

	"github.com/minio/sio"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	codeOK     int = iota // exit successfully
	codeError             // exit because of error
	codeCancel            // exit because of interrupt
)

var (
	cleanChan chan<- int // initialized in init
	cleanFn   = make([]func(int), 0, 3)
)

var (
	listFlag    bool
	decryptFlag bool
	cipherFlag  string
)

func init() {
	flag.BoolVar(&listFlag, "list", false, fmt.Sprintf("%-8s List supported algorithms", ""))
	flag.BoolVar(&decryptFlag, "d", false, fmt.Sprintf("%-8s Decrypt", ""))

	flag.StringVar(&cipherFlag, "cipher", "", fmt.Sprintf("%-8s Specify cipher - default: platform depended", "string"))

	flag.Usage = func() {
		printFlag := func(f *flag.Flag) {
			fmt.Fprintf(os.Stderr, "  -%-6s %s\n", f.Name, f.Usage)
		}
		fmt.Fprintf(os.Stderr, "Usage: %s [FLAGS] [ARGUMENTS...]\n\n", os.Args[0])
		flag.VisitAll(printFlag)
		os.Exit(codeOK)
	}

	cleanCh := make(chan int, 1)
	cleanChan = cleanCh
	go func() {
		code := <-cleanCh
		for _, f := range cleanFn {
			f(code)
		}
		os.Exit(code)
	}()

	// handle user termination
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		_ = <-sigChan
		cleanChan <- codeCancel // try to exit gracefully
		runtime.Goexit()
	}()
}

var supportedCiphers = map[string]string{
	"AES256":   "AES-256 GCM",
	"C20P1305": "ChaCah20 Poly1305",
}

func main() {
	flag.Parse()
	if listFlag {
		printCiphers()
	}

	ciphersuite := cipherSuites()
	in, out := parseIOArgs()
	key := deriveKey(out, in)

	cfg := sio.Config{Key: key, CipherSuites: ciphersuite}
	if decryptFlag {
		decrypt(out, in, cfg)
	} else {
		encrypt(out, in, cfg)
	}
	return
}

func exit(code int) {
	cleanChan <- code
	runtime.Goexit()
}

func printCiphers() {
	ciphers := make([]string, 0, len(supportedCiphers))
	for c := range supportedCiphers {
		ciphers = append(ciphers, c)
	}
	sort.Strings(ciphers)

	fmt.Fprintln(os.Stdout, "Supported ciphers:")
	for _, c := range ciphers {
		fmt.Fprintf(os.Stdout, "\t%-8s : %s\n", c, supportedCiphers[c])
	}
	exit(codeOK)
}

func cipherSuites() []byte {
	switch cipherFlag {
	default:
		fmt.Fprintf(os.Stderr, "Unknown cipher: %s\n", cipherFlag)
		exit(codeError)
		return nil // make compiler happy
	case "":
		return []byte{} // use platform specific cipher
	case "AES256":
		return []byte{sio.AES_256_GCM}
	case "C20P1305":
		return []byte{sio.CHACHA20_POLY1305}
	}
}

func parseIOArgs() (*os.File, *os.File) {
	switch args := flag.Args(); len(args) {
	default:
		fmt.Fprintf(os.Stderr, "Unknown arguments: %s\n", args[2:])
		exit(codeError)
		return nil, nil // make compiler happy
	case 0:
		return os.Stdin, os.Stdout
	case 1:
		in, err := os.Open(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open '%s': %v\n", args[0], err)
			exit(codeError)
		}
		cleanFn = append(cleanFn, func(code int) { in.Close() })
		return in, os.Stdout
	case 2:
		in, err := os.Open(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open '%s': %v\n", args[0], err)
			exit(codeError)
		}
		out, err := os.Create(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create '%s': %v\n", args[1], err)
			exit(codeError)
		}
		cleanFn = append(cleanFn, func(code int) {
			out.Close()
			if code != codeOK { // remove file on error
				os.Remove(out.Name())
			}
		})
		return in, out
	}
}

func readPassword(src *os.File) []byte {
	state, err := terminal.GetState(int(src.Fd()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to read password:", err)
		exit(codeError)
	}
	cleanFn = append(cleanFn, func(code int) {
		stat, _ := terminal.GetState(int(src.Fd()))
		if code == codeCancel && stat != nil && *stat != *state {
			fmt.Fprintln(src, "\nFailed to read password: Interrupted")
		}
		terminal.Restore(int(src.Fd()), state)
	})

	fmt.Fprint(src, "Enter password:")
	password, err := terminal.ReadPassword(int(src.Fd()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to read password:", err)
		exit(codeError)
	}
	fmt.Fprintln(src, "")
	if len(password) == 0 {
		fmt.Fprintln(os.Stderr, "Failed to read password: No password")
		exit(codeOK)
	}
	return password
}

func deriveKey(dst, src *os.File) []byte {
	password, salt := []byte{}, make([]byte, 32)
	if src == os.Stdin {
		password = readPassword(os.Stderr)
	} else {
		password = readPassword(os.Stdin)
	}
	if decryptFlag {
		if _, err := io.ReadFull(src, salt); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read salt from '%s'\n", src.Name())
			exit(codeError)
		}
	} else {
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate random salt '%s'\n", src.Name())
			exit(codeError)
		}
		if _, err := dst.Write(salt); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write salt to '%s'\n", dst.Name())
			exit(codeError)
		}
	}
	key, err := scrypt.Key(password, salt, 32768, 16, 1, 32)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to derive key from password and salt")
		exit(codeError)
	}
	return key
}

func encrypt(dst, src *os.File, cfg sio.Config) {
	if _, err := sio.Encrypt(dst, src, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encrypt: '%s'\n", src.Name())
		exit(codeError)
	}
}

func decrypt(dst, src *os.File, cfg sio.Config) {
	if _, err := sio.Decrypt(dst, src, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decrypt: '%s'\n", src.Name())
		exit(codeError)
	}
}
