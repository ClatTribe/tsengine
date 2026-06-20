// Package main is a deliberately benign program used as an FP-control
// fixture: it contains no injection sinks, no hardcoded secrets, no unsafe
// deserialization, and no vulnerable dependencies. A correct SAST/SCA/secret
// scan of this tree raises ZERO high/critical findings — any that appear are
// false positives (see ../fixture.json).
package main

import (
	"fmt"
	"strconv"
)

func main() {
	total := 0
	for _, s := range []string{"1", "2", "3"} {
		n, err := strconv.Atoi(s)
		if err != nil {
			continue
		}
		total += n
	}
	fmt.Println("total:", total)
}
