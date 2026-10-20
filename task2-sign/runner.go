package sign

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	tsscommon "github.com/bnb-chain/tss-lib/v4/common"
	tsscrypto "github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v4/tss"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/purplecity/bnb_chain_tss/task3-address/derive"
)

type PeerMessage struct {
	Frame *LinkFrame
	Party *tss.PartyID
}

type peerSender func(context.Context, *LinkFrame) error

func RunSigningParty(ctx context.Context, nodeID string, wallet *Wallet, requestID, sessionID string, digest, nonce []byte, siteID, index uint32, inbound <-chan PeerMessage, send peerSender) (*tsscommon.SignatureData, error) {
	if len(digest) != 32 {
		return nil, errors.New("digest must be exactly 32 bytes")
	}
	if len(nonce) != 32 || new(big.Int).SetBytes(nonce).Sign() == 0 {
		return nil, errors.New("session nonce must be a non-zero 32-byte value")
	}
	if wallet == nil || !wallet.PublicKeyMatchesMetadata() {
		return nil, errors.New("wallet key metadata validation failed")
	}
	derived, tweak, err := derive.Derive(wallet.Meta, siteID, index)
	if err != nil {
		return nil, err
	}
	pubBytes, err := hex.DecodeString(derived.PublicKey)
	if err != nil {
		return nil, err
	}
	childPub, err := gethcrypto.UnmarshalPubkey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("decode derived child public key: %w", err)
	}
	signSave := wallet.Share
	signSave.BigXj = append([]*tsscrypto.ECPoint(nil), wallet.Share.BigXj...)
	var kdd *big.Int
	if tweak.Sign() != 0 {
		adjusted := []keygen.LocalPartySaveData{signSave}
		if err := signing.UpdatePublicKeyAndAdjustBigXj(tweak, adjusted, childPub, tss.S256()); err != nil {
			return nil, fmt.Errorf("adjust child public key: %w", err)
		}
		// The helper updates ECDSAPub on each slice element by value. Keep that
		// updated element; otherwise BigXj would describe the child key while
		// ECDSAPub still described the root key.
		signSave = adjusted[0]
		kdd = tweak
	} else {
		signSave.ECDSAPub, err = tsscrypto.NewECPoint(tss.S256(), childPub.X, childPub.Y)
		if err != nil {
			return nil, err
		}
	}
	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(wallet.PartyIDs), mustLocalParty(wallet), 3, 1)
	params.SetSessionNonce(new(big.Int).SetBytes(nonce))
	out := make(chan tss.Message, 256)
	end := make(chan *tsscommon.SignatureData, 1)
	party := signing.NewLocalPartyWithKDD(new(big.Int).SetBytes(digest), params, signSave, kdd, out, end)
	if err := party.Start(); err != nil {
		return nil, fmt.Errorf("start signing party: %w", err)
	}

	partyByID := make(map[string]*tss.PartyID, len(wallet.PartyIDs))
	for _, id := range wallet.PartyIDs {
		partyByID[id.Id] = id
	}
	dispatch := func(msg tss.Message) error {
		if msg == nil {
			return nil
		}
		payload, routing, err := msg.WireBytes()
		if err != nil {
			return fmt.Errorf("encode tss message: %w", err)
		}
		from := msg.GetFrom()
		if from == nil || from.Id != nodeID {
			return errors.New("tss-lib emitted message with unexpected sender")
		}
		recipients := msg.GetTo()
		if recipients == nil {
			recipients = make([]*tss.PartyID, 0, 2)
			for _, id := range wallet.PartyIDs {
				if id.Id != nodeID {
					recipients = append(recipients, id)
				}
			}
		}
		for _, to := range recipients {
			if to == nil || to.Id == nodeID {
				return errors.New("tss-lib emitted invalid peer recipient")
			}
			frame := &LinkFrame{Type: "TSS", From: nodeID, To: to.Id, WalletID: wallet.Meta.WalletID, RequestID: requestID, SessionID: sessionID, Broadcast: routing.IsBroadcast, Payload: payload}
			if err := send(ctx, frame); err != nil {
				return fmt.Errorf("send tss message to %s: %w", to.Id, err)
			}
		}
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-end:
			if result == nil {
				return nil, errors.New("tss-lib returned an empty signature")
			}
			if len(result.R) == 0 || len(result.S) == 0 {
				return nil, errors.New("tss-lib returned an incomplete signature")
			}
			r, s := new(big.Int).SetBytes(result.R), new(big.Int).SetBytes(result.S)
			if !ecdsa.Verify(childPub, digest, r, s) {
				return nil, errors.New("tss-lib signature does not verify against derived child public key")
			}
			return result, nil
		case in := <-inbound:
			if in.Frame == nil || in.Party == nil {
				return nil, errors.New("invalid incoming peer frame")
			}
			if in.Frame.Type != "TSS" || in.Frame.WalletID != wallet.Meta.WalletID || in.Frame.RequestID != requestID || in.Frame.SessionID != sessionID || in.Frame.To != nodeID {
				return nil, errors.New("peer frame does not match active signing session")
			}
			if partyByID[in.Party.Id] == nil {
				return nil, errors.New("peer sender is not in active roster")
			}
			ok, updateErr := party.UpdateFromBytes(in.Frame.Payload, in.Party, in.Frame.Broadcast)
			if updateErr != nil {
				return nil, fmt.Errorf("update signing party from %s: %w", in.Party.Id, updateErr)
			}
			if !ok {
				return nil, fmt.Errorf("signing party rejected message from %s", in.Party.Id)
			}
		case msg := <-out:
			if err := dispatch(msg); err != nil {
				return nil, err
			}
		}
	}
}

func mustLocalParty(wallet *Wallet) *tss.PartyID {
	id, err := wallet.LocalPartyID()
	if err != nil {
		panic(err)
	}
	return id
}
