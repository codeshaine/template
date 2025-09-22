package p2ms

import (
	"errors"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

func getByteForNumber(n uint) ([]byte, error) {

	if n >= 1 && n <= 16 {
		return []byte{(script.Op1 - 1 + byte(n))}, nil
	}

	//application level limit (for now)
	return nil, errors.New("max limit key limit is 16")
}

func Lock(publicKeys []*ec.PublicKey, minSig, maxSig int) (*script.Script, error) {

	//  1 + 33 (for each public key) + n * (number of public key) + 1  + 1

	if maxSig != len(publicKeys) {
		return nil, errors.New("incorrect public key number and max sig needed")
	}

	if minSig < 1 {
		return nil, errors.New("minimum signature must be greater than 1")
	}

	if maxSig < 1 {
		return nil, errors.New("maximum signature must be greater than 1")
	}

	b := make([]byte, 0)

	minSigBytes, err := getByteForNumber(uint(minSig))
	if err != nil {
		return nil, err
	}

	b = append(b, minSigBytes...)

	for _, key := range publicKeys {
		b = append(b, script.OpDATA33)
		b = append(b, key.Compressed()...)
	}
	maxSigBytes, err := getByteForNumber(uint(maxSig))
	if err != nil {
		return nil, err
	}

	b = append(b, maxSigBytes...)
	b = append(b, script.OpCHECKMULTISIG)

	s := script.Script(b)

	return &s, nil
}

func P2MSUnlock(keys []*ec.PrivateKey, sigHashFlag *sighash.Flag) (*P2MS, error) {
	for _, key := range keys {
		if key == nil {
			return nil, errors.New("private key not supplied")
		}
	}

	if sigHashFlag == nil {
		shf := sighash.AllForkID
		sigHashFlag = &shf
	}

	p := &P2MS{PrivateKeys: keys, SigHashFlag: sigHashFlag}

	return p, nil
}

type P2MS struct {
	PrivateKeys []*ec.PrivateKey
	SigHashFlag *sighash.Flag
}

func (p *P2MS) Sign(tx *transaction.Transaction, inputIndex uint32) (*script.Script, error) {

	input := tx.Inputs[inputIndex]

	if input.SourceTxOutput() == nil {
		return nil, errors.New("'PreviousTx' not supplied")
	}

	s := &script.Script{}

	//appending dummy value because of  checkmutlisig's bug
	err := s.AppendOpcodes(script.Op0)
	if err != nil {
		return nil, err
	}

	for _, key := range p.PrivateKeys {
		sh, err := tx.CalcInputSignatureHash(inputIndex, *p.SigHashFlag)
		if err != nil {
			return nil, err
		}

		sig, err := key.Sign(sh)
		if err != nil {
			return nil, err
		}

		signature := sig.Serialize()

		sigBuf := make([]byte, 0)
		sigBuf = append(sigBuf, signature...)
		sigBuf = append(sigBuf, uint8(*p.SigHashFlag))

		if err = s.AppendPushData(sigBuf); err != nil {
			return nil, err
		}
	}

	return s, nil
}

func (p *P2MS) EstimateLength(tx *transaction.Transaction, inputIndex uint32) uint32 {
	//~ 73 + 73 + 2 +1
	//~ 73(public key can be 71,72 or 73)  + 2 (pushdata op code) +1 (dummy data)
	return uint32((len(p.PrivateKeys) * 73) + len(p.PrivateKeys) + 1)
}
