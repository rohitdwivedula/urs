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
	std::string keyRing = "02dcdb96d05d6cd36ce7014a69ebce8b48f8d7de46ce3bfa99482af65284697e13 02b266b2c32ba5fc8d203c8f3e65e50480dfc10404ed089bad5f9ac5a45ffa4251 031ea759e3401463b82e2132535393076dde89bf2af7fc550f0793126669ffb5cd";
	std::string message = "pollID";
	std::string vote = "myVoteIs10";

	GoString kp_g = convert(keyPair);
	GoString kr_g = convert(keyRing);
	GoString m_g = convert(message);
	GoString v_g = convert(vote);

	char* ans = SignMV(
		kp_g, kr_g, m_g, v_g
	);
	std::string s(ans);
	FreeString(ans);
	std::cout << s << std::endl;

	GoString s_g = convert(s);
	int a = VerifyMV(kr_g, m_g, v_g, s_g);
	bool b = (a != 0);
	std::cout << "Veridication Status: " << a << std::endl;
}