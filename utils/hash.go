package utils

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
	"hash"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/okex/exchain-ethereum-compatible/internal"
)

func LegacyHash(signtx *types.Transaction) (common.Hash, error) {
	return txhash(signtx, sha256Hash, aminoEncode)
}

func Hash(signtx *types.Transaction) (common.Hash, error) {
	return txhash(signtx, keccak256Hash, rlpEncode)
}

func txhash(signtx *types.Transaction,
	hash func(data []byte) common.Hash,
	encode func(*internal.MsgEthereumTx) ([]byte, error),
) (common.Hash, error) {
	if signtx.Type() != types.LegacyTxType {
		return common.Hash{}, errors.New("only supported eip-155 legacy transaction")
	}

	v, r, s := signtx.RawSignatureValues()
	msg := internal.NewMsgEthereumTx(
		signtx.Nonce(),
		signtx.GasPrice(),
		signtx.Gas(),
		signtx.To(),
		signtx.Value(),
		signtx.Data(),
		v,
		r,
		s,
	)

	bins, err := encode(&msg)
	if err != nil {
		return common.Hash{}, errors.New(fmt.Sprintf("failed to marshal msg: %v", err))
	}

	return hash(bins), nil
}

func sha256Hash(data []byte) common.Hash {
	hash := sha256.Sum256(data)
	return common.BytesToHash(hash[:])
}

func keccak256Hash(data []byte) common.Hash {
	hash := sum(data)
	return common.BytesToHash(hash[:])
}

func rlpEncode(msg *internal.MsgEthereumTx) ([]byte, error) {
	return rlp.EncodeToBytes(&msg.Data)
}

func aminoEncode(msg *internal.MsgEthereumTx) ([]byte, error) {
	cdc := internal.GetModuleCdc()
	return cdc.MarshalBinaryLengthPrefixed(msg)
}

var keccakPool = sync.Pool{
	// NewLegacyKeccak256 uses non-standard padding
	// and is incompatible with sha3.Sum256
	New: func() interface{} { return sha3.NewLegacyKeccak256() },
}

// Sum returns the non-standard Keccak256 of the bz.
func sum(bz []byte) []byte {
	sha := keccakPool.Get().(hash.Hash)
	defer func() {
		// better to reset before putting it to the pool
		sha.Reset()
		keccakPool.Put(sha)
	}()
	sha.Reset()
	sha.Write(bz)
	return sha.Sum(nil)
}
