#include <bits/stdc++.h>
#include "urs.h"

void print(GoString& x){
	fwrite(x.p, 1, x.n, stdout);
}

GoString convert(std::string& x){
	GoString x_g = {
		x.c_str(),
		(long int) x.length()
	};
	return x_g;
}

int main(){
	std::string keyPair ="1NBN9d4pZutCykB3Why5f3V7hG27EbcqKb 4fb0b355ad56c1d19ebb30591a036dfb6a2c20d9836b22c23dc521ea53e08cd4 02dcdb96d05d6cd36ce7014a69ebce8b48f8d7de46ce3bfa99482af65284697e13";
	std::string keyRing = "024627032575180c2773b3eedd3a163dc2f3c6c84f9d0a1fc561a9578a15e6d0e3 02b266b2c32ba5fc8d203c8f3e65e50480dfc10404ed089bad5f9ac5a45ffa4251 031ea759e3401463b82e2132535393076dde89bf2af7fc550f0793126669ffb5cd";
	std::string message = "ROHIT";
	GoString kp_g = convert(keyPair);
	GoString kr_g = convert(keyRing);
	GoString msg_g = convert(message);
	char* ans = sign(
		kp_g, kr_g, msg_g
	);
	printf("%s\n", ans);
	freeString(ans);
	return 0;
}