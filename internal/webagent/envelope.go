package webagent

import (
	"github.com/ClatTribe/tsengine/internal/envelope"
)

// envelope.go is ADR 0032 D7: the implementation moved to internal/envelope so
// every model-backed subsystem shares ONE primitive (request walls here, token
// budgets in the sweep stage). This file keeps the webagent-facing names as
// aliases, so all existing signatures and tests compile unchanged.
//
// Nil-safe everywhere: a nil *Envelope means "no shared envelope" — exactly
// today's serial behavior (the strangler rule).

type Envelope = envelope.Envelope

// NewEnvelope authorizes n requests for the whole engagement.
func NewEnvelope(n int) *Envelope { return envelope.New(n) }
