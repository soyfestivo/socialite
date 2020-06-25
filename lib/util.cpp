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
#include <iomanip> 

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

const char base64_url_alphabet[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
};

std::string base64Encode(const std::string& in) {
  std::string out;
  int val =0, valb=-6;
  size_t len = in.length();
  unsigned int i = 0;
  for (i = 0; i < len; i++) {
    unsigned char c = in[i];
    val = (val<<8) + c;
    valb += 8;
    while (valb >= 0) {
      out.push_back(base64_url_alphabet[(val>>valb)&0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6) {
    out.push_back(base64_url_alphabet[((val<<8)>>(valb+8))&0x3F]);
  }
  return out;
}

std::string base64Decode(const std::string& in) {
  std::string out;
  std::vector<int> T(256, -1);
  unsigned int i;
  for (i =0; i < 64; i++) T[base64_url_alphabet[i]] = i;

  int val = 0, valb = -8;
  for (i = 0; i < in.length(); i++) {
    unsigned char c = in[i];
    if (T[c] == -1) break;
    val = (val<<6) + T[c];
    valb += 6;
    if (valb >= 0) {
      out.push_back(char((val>>valb)&0xFF));
      valb -= 8;
    }
  }
  return out;
}

std::string removeChar(std::string str, char c) {
	std::stringstream ss;
	for(int i = 0; i < str.length(); i++) {
		if(str[i] != c) {
			ss << str[i];
		}
	}
	return ss.str();
}

std::string Socialite::Util::generateJwt(Json::Value value, std::string secretKey) {
	Json::Value jwtHeader;
	jwtHeader["alg"] = "HS256";
	jwtHeader["typ"] = "JWT";

	std::string jwtHeaderBase64 = removeChar(base64Encode(jwtHeader.toStyledString()), '=');
	std::string contentBase64 = removeChar(base64Encode(value.toStyledString()), '=');
	std::string messageToEncrypt = jwtHeaderBase64 + "." + contentBase64;

	unsigned char hash[32];

    HMAC_CTX hmac;
    HMAC_CTX_init(&hmac);
    HMAC_Init_ex(&hmac, &secretKey[0], secretKey.length(), EVP_sha256(), NULL);
    HMAC_Update(&hmac, (unsigned char*) &messageToEncrypt[0], messageToEncrypt.length());
    unsigned int len = 32;
    HMAC_Final(&hmac, hash, &len);
    HMAC_CTX_cleanup(&hmac);

    std::stringstream ss;
    ss << std::setfill('0');
    for (int i = 0; i < len; i++) {
        ss  << hash[i];
    }

	std::string hmacSignatureBase64 = removeChar(base64Encode(ss.str()), '=');	

	return jwtHeaderBase64 + "." + contentBase64 + "." + hmacSignatureBase64;
}

std::string Socialite::Util::generateRandomString(int length) {
	const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

	char buffer[length+1];

    for (int i = 0; i < length; ++i) {
        buffer[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    buffer[length] = 0;
	return std::string(buffer);
}

Json::Value Socialite::Util::verifyAndReadJwt(std::string jwt, std::string secretKey) {
	smatch matcher;
	regex jwtShape("^.*\\.(.*)\\..*$");
	std::string payload;
	if(regex_match(jwt, matcher, jwtShape)) {
		payload = base64Decode(matcher[1]);
	}
	Json::Value root;
	Json::Reader reader;
	reader.parse(payload, root);
	if(generateJwt(root, secretKey) != jwt) {
		throw -1;
	}
	return root;
}