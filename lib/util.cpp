#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctime>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <math.h>
#include <cmath>
#include <float.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <regex>

#include "util.h"

using std::string;
using std::regex;
using std::smatch;

string Socialite::Util::toHttpTimestamp(time_t stamp) {
	struct tm* t = gmtime(&stamp);
	char buffer[256];
	strftime(buffer, 256, "%a, %e %b %Y %T GMT", t);
	return string(buffer);
}

time_t Socialite::Util::parseHttpTimestamp(string stamp) {
	//Mon, 13 Jun 2016 21:24:31 GMT
	smatch matcher; // 
	regex shape("^(?:[A-Za-z]{3}), ([0-9]{1,2}) ([A-Za-z]{3,4}) ([0-9]{4}) ([0-9]{1,2}):([0-9]{1,2}):([0-9]{1,2}) ([A-Za-z]{3,4})$");

	const char* dates[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

	if(regex_match(stamp, matcher, shape)) {
		regex_search(stamp, matcher, shape);
		//cout << matcher[4] << "\n";

		int m = 0;
		string tmp = matcher[2];
		char* month = (char*) tmp.c_str();
		for(int i = 0; i < 12; i++) {
			if(strcmp(dates[i], month) == 0) {
				m = i;
			}
		}

		time_t now;
		time(&now);
		struct tm* t = localtime(&now);
		t->tm_year = std::stoi(matcher[3]) - 1900;
		t->tm_mon = m;
		t->tm_mday = std::stoi(matcher[1]);
		t->tm_hour = std::stoi(matcher[4]);
		t->tm_min = std::stoi(matcher[5]);
		t->tm_sec = std::stoi(matcher[6]);
		return mktime(t);
	}

	return (time_t) 0;
}

string Socialite::Util::getTimestampTime(time_t stamp) {
	struct tm* t = localtime(&stamp);
	char buffer[256];
	strftime(buffer, 256, "%T", t);
	return string(buffer);
}

void Socialite::Util::mapPostData(std::map<std::string, std::string>& mapper, std::string str) {
	std::smatch matcher;
	std::regex shape("([A-Za-z0-9\\-]+)=([^&]*)");
	//std::cout << "Socialite::Util::mapPostData " << str << "\n";
	while(std::regex_search(str, matcher, shape)) {
		mapper[string(matcher[1])] = string(matcher[2]);
		str = matcher.suffix().str();
	}
}

string Socialite::Util::sha256(string str) {
	char* c_string = (char*) str.c_str();
	char outputBuffer[65];
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, c_string, strlen(c_string));
	SHA256_Final(hash, &sha256);
	int i = 0;
	for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
	}
	outputBuffer[64] = 0;
	return string(outputBuffer);
}