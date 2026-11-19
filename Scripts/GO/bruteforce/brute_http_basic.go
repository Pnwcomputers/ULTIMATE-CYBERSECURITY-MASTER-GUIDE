package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "Retired: former remote HTTP password-guessing example. Use approved identity-provider controls and authentication logs.")
	os.Exit(2)
}
