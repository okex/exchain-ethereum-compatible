package utils

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/okex/exchain-ethereum-compatible/internal"
)

func Hash(signtx *types.Transaction) (common.Hash, error) {
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

	bins, err := marshal(msg)
	if err != nil {
		return common.Hash{}, errors.New(fmt.Sprintf("failed to marshal msg: %v", err))
	}

	hash := sha256.Sum256(bins)
	return common.BytesToHash(hash[:]), nil
}

func marshal(msg internal.MsgEthereumTx) ([]byte, error) {
	cdc := internal.GetModuleCdc()
	return cdc.MarshalBinaryLengthPrefixed(msg)
}
