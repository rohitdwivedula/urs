package main

import (
	"fmt"
)

/*
#include <stdio.h>
static void myprint(char* s) {
	printf("%s\n", s);
}
*/
import "C"

func main() {
	kp := "1NBN9d4pZutCykB3Why5f3V7hG27EbcqKb 4fb0b355ad56c1d19ebb30591a036dfb6a2c20d9836b22c23dc521ea53e08cd4 02dcdb96d05d6cd36ce7014a69ebce8b48f8d7de46ce3bfa99482af65284697e13"
	kr := "02dcdb96d05d6cd36ce7014a69ebce8b48f8d7de46ce3bfa99482af65284697e13 02b266b2c32ba5fc8d203c8f3e65e50480dfc10404ed089bad5f9ac5a45ffa4251 031ea759e3401463b82e2132535393076dde89bf2af7fc550f0793126669ffb5cd"
	m := "pollID"
	v := "myVoteIs10"

	s := SignMV(kp, kr, m, v)
	fmt.Printf("SINATURE:\n\n")
	C.myprint(s)

	a := VerifyMV(kr, m, v, C.GoString(s))
	fmt.Printf("%v", a)
	FreeString(s)
}
