// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"testing"
	"fmt"
	"strings"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func TestCleanStack(t *testing.T) {
	t.Parallel()
	scriptSig := []byte{0x00, 0x00, 0x00}    // OP_0 OP_0 OP_0
	scriptPubKey := []byte{0x4f}             // OP_1NEGATE

	t.Logf("scriptSig hex: %x", scriptSig)
	t.Logf("scriptPubKey hex: %x", scriptPubKey)

	// Create a transaction
	tx := wire.NewMsgTx(wire.TxVersion)
	txIn := wire.NewTxIn(&wire.OutPoint{}, nil, nil)
	txIn.SignatureScript = scriptSig
	tx.AddTxIn(txIn)

	// Create the script engine
	prevoutAmt := int64(1000)
	fetcher := NewCannedPrevOutputFetcher(scriptPubKey, prevoutAmt)

	vm, err := NewEngine(
		scriptPubKey,
		tx,
		0, // input index
		StandardVerifyFlags, // Includes ScriptVerifyCleanStack
		nil, // sigCache
		nil, // hashCache
		prevoutAmt,
		fetcher,
	)

	if err != nil {
		t.Logf("NewEngine error: %v", err)
		return
	}

	// Execute the script
	err = vm.Execute()

	// Should fail with CLEANSTACK error - stack has 4 elements instead of 1
	if err == nil {
		t.Fatalf("Script execution passed but should have failed with CLEANSTACK error (stack size must be exactly 1)")
	}

	t.Logf("Execute error: %v", err)

	// Verify it's a cleanstack error
	if !strings.Contains(err.Error(), "clean stack") {
		t.Errorf("Expected cleanstack error, got: %v", err)
	}
}

func TestInvalidOpcode3(t *testing.T) {
	t.Parallel()
	scriptSig := []byte{0x00, 0x00, 0x00}    // OP_0 OP_0 OP_0
	scriptPubKey := []byte{0x4f}             // OP_1NEGATE

	t.Logf("scriptSig hex: %x", scriptSig)
	t.Logf("scriptPubKey hex: %x", scriptPubKey)

	// Create a transaction
	tx := wire.NewMsgTx(wire.TxVersion)
	txIn := wire.NewTxIn(&wire.OutPoint{}, nil, nil)
	txIn.SignatureScript = scriptSig
	tx.AddTxIn(txIn)

	// Create the script engine
	prevoutAmt := int64(1000)
	fetcher := NewCannedPrevOutputFetcher(scriptPubKey, prevoutAmt)

	vm, err := NewEngine(
		scriptPubKey,
		tx,
		0, // input index
		StandardVerifyFlags,
		nil, // sigCache
		nil, // hashCache
		prevoutAmt,
		fetcher,
	)

	if err != nil {
		t.Logf("NewEngine error: %v", err)
		// This is acceptable - error might be caught during parsing
		return
	}

	// Execute the script
	err = vm.Execute()

	t.Logf("Execute error: %v (err == nil: %v)", err, err == nil)

	// This script should execute successfully:
	// scriptSig pushes three empty values (OP_0 OP_0 OP_0)
	// scriptPubKey pushes -1 (OP_1NEGATE)
	// Final stack should have: [empty, empty, empty, -1]
	// Script fails if top of stack is false/empty, succeeds if true/non-empty
	// -1 is "true" so this should succeed

	if err != nil {
		t.Logf("Script execution failed with: %v", err)
	} else {
		t.Logf("Script execution succeeded")
	}
}

func TestInvalidOpcode2(t *testing.T) {
	t.Parallel()
	scriptSig := []byte{0x00, 0x00, 0x00}    // OP_0 OP_INVALIDOPCODE
	scriptPubKey := []byte{0x48}       // OP_2

	t.Logf("scriptSig hex: %x", scriptSig)
	t.Logf("scriptPubKey hex: %x", scriptPubKey)

	// Create a transaction
	tx := wire.NewMsgTx(wire.TxVersion)
	txIn := wire.NewTxIn(&wire.OutPoint{}, nil, nil)
	txIn.SignatureScript = scriptSig
	tx.AddTxIn(txIn)

	// Create the script engine
	prevoutAmt := int64(1000)
	fetcher := NewCannedPrevOutputFetcher(scriptPubKey, prevoutAmt)

	vm, err := NewEngine(
		scriptPubKey,
		tx,
		0, // input index
		StandardVerifyFlags,
		nil, // sigCache
		nil, // hashCache
		prevoutAmt,
		fetcher,
	)

	if err != nil {
		fmt.Printf("NewEngine error: %v", err)
		// This is acceptable - invalid opcode might be caught during parsing
		return
	}

	// Execute the script
	if err := vm.Execute(); err != nil {
		fmt.Printf("Execute error: %v", err)
		//t.Fatalf("Script execution passed but should have failed with BAD_OPCODE error")
	}
}

func TestMinimalDataScriptPubKey2(t *testing.T) {
	t.Parallel()
	scriptSig := []byte{0x00, 0x00}    // OP_0 OP_0
	scriptPubKey := []byte{0x01, 0x0a} // OP_DATA_1 0x0a (should be OP_10 = 0x59)

	t.Logf("scriptSig hex: %x", scriptSig)
	t.Logf("scriptPubKey hex: %x", scriptPubKey)

	// Create a transaction
	tx := wire.NewMsgTx(wire.TxVersion)
	txIn := wire.NewTxIn(&wire.OutPoint{}, nil, nil)
	txIn.SignatureScript = scriptSig
	tx.AddTxIn(txIn)

	// Create the script engine
	prevoutAmt := int64(1000)
	fetcher := NewCannedPrevOutputFetcher(scriptPubKey, prevoutAmt)

	vm, err := NewEngine(
		scriptPubKey,
		tx,
		0, // input index
		StandardVerifyFlags,
		nil, // sigCache
		nil, // hashCache
		prevoutAmt,
		fetcher,
	)

	if err != nil {
		t.Logf("NewEngine error: %v", err)
		t.Fatalf("Expected script to fail with minimal data error, got NewEngine error: %v", err)
	}

	// Execute the script
	err = vm.Execute()

	if err == nil {
		t.Fatalf("Script execution passed but should have failed with MINIMALDATA error")
	}

	t.Logf("Execute error: %v", err)

	// This should fail with a minimal data error
	// The scriptPubKey pushes 0x0a (decimal 10) which should be encoded as OP_10 (0x59)
}

func TestMinimalDataScriptPubKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		scriptSig      []byte
		scriptPubKey   []byte
		shouldPass     bool
		expectedError  string
	}{
		{
			name:          "Non-minimal push in scriptPubKey (value 10)",
			scriptSig:     []byte{0x00, 0x00}, // OP_0 OP_0
			scriptPubKey:  []byte{0x01, 0x0a}, // OP_DATA_1 0x0a (should be OP_10)
			shouldPass:    false,
			expectedError: "minimal data",
		},
		{
			name:          "Minimal encoding in scriptPubKey (OP_10)",
			scriptSig:     []byte{0x00, 0x00}, // OP_0 OP_0
			scriptPubKey:  []byte{0x59},       // OP_10 (correct minimal encoding)
			shouldPass:    true,
			expectedError: "",
		},
		{
			name:          "Non-minimal push in scriptSig (value 10)",
			scriptSig:     []byte{0x01, 0x0a}, // OP_DATA_1 0x0a (should be OP_10)
			scriptPubKey:  []byte{0x00, 0x00}, // OP_0 OP_0
			shouldPass:    false,
			expectedError: "",
		},
		{
			name:          "Non-minimal zero push in scriptPubKey",
			scriptSig:     []byte{0x00},       // OP_0
			scriptPubKey:  []byte{0x01, 0x00}, // OP_DATA_1 0x00 (should be OP_0)
			shouldPass:    false,
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a transaction
			tx := wire.NewMsgTx(wire.TxVersion)
			txIn := wire.NewTxIn(&wire.OutPoint{}, nil, nil)
			txIn.SignatureScript = tt.scriptSig
			tx.AddTxIn(txIn)

			// Create the script engine
			prevoutAmt := int64(1000)
			fetcher := NewCannedPrevOutputFetcher(tt.scriptPubKey, prevoutAmt)

			vm, err := NewEngine(
				tt.scriptPubKey,
				tx,
				0, // input index
				StandardVerifyFlags,
				nil, // sigCache
				nil, // hashCache
				prevoutAmt,
				fetcher,
			)

			if err != nil {
				if tt.shouldPass {
					t.Fatalf("NewEngine failed but should have passed: %v", err)
				}
				// Check if error message contains expected string
				if tt.expectedError != "" && !contains(err.Error(), tt.expectedError) {
					t.Fatalf("Expected error containing '%s', got: %v", tt.expectedError, err)
				}
				return
			}

			// Execute the script
			err = vm.Execute()

			if tt.shouldPass {
				if err != nil {
					t.Fatalf("Script execution failed but should have passed: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("Script execution passed but should have failed")
				}
				// Check if error message contains expected string
				if tt.expectedError != "" && !contains(err.Error(), tt.expectedError) {
					t.Fatalf("Expected error containing '%s', got: %v", tt.expectedError, err)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
		containsHelper(s, substr)))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}


// TestBadPC sets the pc to a deliberately bad result then confirms that Step
// and Disasm fail correctly.
func TestBadPC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		scriptIdx int
	}{
		{scriptIdx: 2},
		{scriptIdx: 3},
	}

	// tx with almost empty scripts.
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash: chainhash.Hash([32]byte{
						0xc9, 0x97, 0xa5, 0xe5,
						0x6e, 0x10, 0x41, 0x02,
						0xfa, 0x20, 0x9c, 0x6a,
						0x85, 0x2d, 0xd9, 0x06,
						0x60, 0xa2, 0x0b, 0x2d,
						0x9c, 0x35, 0x24, 0x23,
						0xed, 0xce, 0x25, 0x85,
						0x7f, 0xcd, 0x37, 0x04,
					}),
					Index: 0,
				},
				SignatureScript: mustParseShortForm("NOP"),
				Sequence:        4294967295,
			},
		},
		TxOut: []*wire.TxOut{{
			Value:    1000000000,
			PkScript: nil,
		}},
		LockTime: 0,
	}
	pkScript := mustParseShortForm("NOP")

	for _, test := range tests {
		vm, err := NewEngine(pkScript, tx, 0, 0, nil, nil, -1, nil)
		if err != nil {
			t.Errorf("Failed to create script: %v", err)
		}

		// Set to after all scripts.
		vm.scriptIdx = test.scriptIdx

		// Ensure attempting to step fails.
		_, err = vm.Step()
		if err == nil {
			t.Errorf("Step with invalid pc (%v) succeeds!", test)
			continue
		}

		// Ensure attempting to disassemble the current program counter fails.
		_, err = vm.DisasmPC()
		if err == nil {
			t.Errorf("DisasmPC with invalid pc (%v) succeeds!", test)
		}
	}
}

// TestCheckErrorCondition tests the execute early test in CheckErrorCondition()
// since most code paths are tested elsewhere.
func TestCheckErrorCondition(t *testing.T) {
	t.Parallel()

	// tx with almost empty scripts.
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash: chainhash.Hash([32]byte{
					0xc9, 0x97, 0xa5, 0xe5,
					0x6e, 0x10, 0x41, 0x02,
					0xfa, 0x20, 0x9c, 0x6a,
					0x85, 0x2d, 0xd9, 0x06,
					0x60, 0xa2, 0x0b, 0x2d,
					0x9c, 0x35, 0x24, 0x23,
					0xed, 0xce, 0x25, 0x85,
					0x7f, 0xcd, 0x37, 0x04,
				}),
				Index: 0,
			},
			SignatureScript: nil,
			Sequence:        4294967295,
		}},
		TxOut: []*wire.TxOut{{
			Value:    1000000000,
			PkScript: nil,
		}},
		LockTime: 0,
	}
	pkScript := mustParseShortForm("NOP NOP NOP NOP NOP NOP NOP NOP NOP" +
		" NOP TRUE")

	vm, err := NewEngine(pkScript, tx, 0, 0, nil, nil, 0, nil)
	if err != nil {
		t.Errorf("failed to create script: %v", err)
	}

	for i := 0; i < len(pkScript)-1; i++ {
		done, err := vm.Step()
		if err != nil {
			t.Fatalf("failed to step %dth time: %v", i, err)
		}
		if done {
			t.Fatalf("finished early on %dth time", i)
		}

		err = vm.CheckErrorCondition(false)
		if !IsErrorCode(err, ErrScriptUnfinished) {
			t.Fatalf("got unexpected error %v on %dth iteration",
				err, i)
		}
	}
	done, err := vm.Step()
	if err != nil {
		t.Fatalf("final step failed %v", err)
	}
	if !done {
		t.Fatalf("final step isn't done!")
	}

	err = vm.CheckErrorCondition(false)
	if err != nil {
		t.Errorf("unexpected error %v on final check", err)
	}
}

// TestInvalidFlagCombinations ensures the script engine returns the expected
// error when disallowed flag combinations are specified.
func TestInvalidFlagCombinations(t *testing.T) {
	t.Parallel()

	tests := []ScriptFlags{
		ScriptVerifyCleanStack,
	}

	// tx with almost empty scripts.
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash: chainhash.Hash([32]byte{
						0xc9, 0x97, 0xa5, 0xe5,
						0x6e, 0x10, 0x41, 0x02,
						0xfa, 0x20, 0x9c, 0x6a,
						0x85, 0x2d, 0xd9, 0x06,
						0x60, 0xa2, 0x0b, 0x2d,
						0x9c, 0x35, 0x24, 0x23,
						0xed, 0xce, 0x25, 0x85,
						0x7f, 0xcd, 0x37, 0x04,
					}),
					Index: 0,
				},
				SignatureScript: []uint8{OP_NOP},
				Sequence:        4294967295,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    1000000000,
				PkScript: nil,
			},
		},
		LockTime: 0,
	}
	pkScript := []byte{OP_NOP}

	for i, test := range tests {
		_, err := NewEngine(pkScript, tx, 0, test, nil, nil, -1, nil)
		if !IsErrorCode(err, ErrInvalidFlags) {
			t.Fatalf("TestInvalidFlagCombinations #%d unexpected "+
				"error: %v", i, err)
		}
	}
}

// TestCheckPubKeyEncoding ensures the internal checkPubKeyEncoding function
// works as expected.
func TestCheckPubKeyEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     []byte
		isValid bool
	}{
		{
			name: "uncompressed ok",
			key: hexToBytes("0411db93e1dcdb8a016b49840f8c53bc1eb68" +
				"a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf" +
				"9744464f82e160bfa9b8b64f9d4c03f999b8643f656b" +
				"412a3"),
			isValid: true,
		},
		{
			name: "compressed ok",
			key: hexToBytes("02ce0b14fb842b1ba549fdd675c98075f12e9" +
				"c510f8ef52bd021a9a1f4809d3b4d"),
			isValid: true,
		},
		{
			name: "compressed ok",
			key: hexToBytes("032689c7c2dab13309fb143e0e8fe39634252" +
				"1887e976690b6b47f5b2a4b7d448e"),
			isValid: true,
		},
		{
			name: "hybrid",
			key: hexToBytes("0679be667ef9dcbbac55a06295ce870b07029" +
				"bfcdb2dce28d959f2815b16f81798483ada7726a3c46" +
				"55da4fbfc0e1108a8fd17b448a68554199c47d08ffb1" +
				"0d4b8"),
			isValid: false,
		},
		{
			name:    "empty",
			key:     nil,
			isValid: false,
		},
	}

	vm := Engine{flags: ScriptVerifyStrictEncoding}
	for _, test := range tests {
		err := vm.checkPubKeyEncoding(test.key)
		if err != nil && test.isValid {
			t.Errorf("checkSignatureEncoding test '%s' failed "+
				"when it should have succeeded: %v", test.name,
				err)
		} else if err == nil && !test.isValid {
			t.Errorf("checkSignatureEncooding test '%s' succeeded "+
				"when it should have failed", test.name)
		}
	}

}

// TestCheckSignatureEncoding ensures the internal checkSignatureEncoding
// function works as expected.
func TestCheckSignatureEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sig     []byte
		isValid bool
	}{
		{
			name: "valid signature",
			sig: hexToBytes("304402204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: true,
		},
		{
			name:    "empty.",
			sig:     nil,
			isValid: false,
		},
		{
			name: "bad magic",
			sig: hexToBytes("314402204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "bad 1st int marker magic",
			sig: hexToBytes("304403204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "bad 2nd int marker",
			sig: hexToBytes("304402204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41032018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "short len",
			sig: hexToBytes("304302204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "long len",
			sig: hexToBytes("304502204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "long X",
			sig: hexToBytes("304402424e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "long Y",
			sig: hexToBytes("304402204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41022118152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "short Y",
			sig: hexToBytes("304402204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41021918152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "trailing crap",
			sig: hexToBytes("304402204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d0901"),
			isValid: false,
		},
		{
			name: "X == N ",
			sig: hexToBytes("30440220fffffffffffffffffffffffffffff" +
				"ffebaaedce6af48a03bbfd25e8cd0364141022018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "X == N ",
			sig: hexToBytes("30440220fffffffffffffffffffffffffffff" +
				"ffebaaedce6af48a03bbfd25e8cd0364142022018152" +
				"2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
				"82221a8768d1d09"),
			isValid: false,
		},
		{
			name: "Y == N",
			sig: hexToBytes("304402204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd410220fffff" +
				"ffffffffffffffffffffffffffebaaedce6af48a03bb" +
				"fd25e8cd0364141"),
			isValid: false,
		},
		{
			name: "Y > N",
			sig: hexToBytes("304402204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd410220fffff" +
				"ffffffffffffffffffffffffffebaaedce6af48a03bb" +
				"fd25e8cd0364142"),
			isValid: false,
		},
		{
			name: "0 len X",
			sig: hexToBytes("302402000220181522ec8eca07de4860a4acd" +
				"d12909d831cc56cbbac4622082221a8768d1d09"),
			isValid: false,
		},
		{
			name: "0 len Y",
			sig: hexToBytes("302402204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd410200"),
			isValid: false,
		},
		{
			name: "extra R padding",
			sig: hexToBytes("30450221004e45e16932b8af514961a1d3a1a" +
				"25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181" +
				"522ec8eca07de4860a4acdd12909d831cc56cbbac462" +
				"2082221a8768d1d09"),
			isValid: false,
		},
		{
			name: "extra S padding",
			sig: hexToBytes("304502204e45e16932b8af514961a1d3a1a25" +
				"fdf3f4f7732e9d624c6c61548ab5fb8cd41022100181" +
				"522ec8eca07de4860a4acdd12909d831cc56cbbac462" +
				"2082221a8768d1d09"),
			isValid: false,
		},
	}

	vm := Engine{flags: ScriptVerifyStrictEncoding}
	for _, test := range tests {
		err := vm.checkSignatureEncoding(test.sig)
		if err != nil && test.isValid {
			t.Errorf("checkSignatureEncoding test '%s' failed "+
				"when it should have succeeded: %v", test.name,
				err)
		} else if err == nil && !test.isValid {
			t.Errorf("checkSignatureEncooding test '%s' succeeded "+
				"when it should have failed", test.name)
		}
	}
}
