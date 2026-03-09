// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"fmt"
	"time"
)

// Duration represents a time.Duration and supports marshaling/unmarshaling from
// a json string
type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Duration.String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	const op = "api.(Duration).UnmarshalJSON"
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	val, err := time.ParseDuration(str)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	d.Duration = val
	return nil
}
