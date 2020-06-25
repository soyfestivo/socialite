#ifndef _UTIL_H_
#define _UTIL_H_

#include <iostream>
#include <regex>
#include <map>
#include <ctime>
#include <functional>
#include <json/json.h>

namespace Socialite {
	namespace Util {
		// gmt time
		std::string toHttpTimestamp(time_t stamp);
		time_t parseHttpTimestamp(std::string stamp);
		std::string getTimestampTime(time_t stamp);

		void mapPostData(std::map<std::string, std::string>& mapper, std::string);
		std::string sha256(std::string str);

		Json::Value verifyAndReadJwt(std::string jwt, std::string secretKey);
		std::string generateJwt(Json::Value value, std::string secretKey);

		std::string generateRandomString(int length);
	}
}

#endif