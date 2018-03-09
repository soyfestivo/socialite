#include <iostream>
#include <functional>
#include <map>

namespace Socialite {
	namespace Web {
		std::string Get(std::string url);
		std::string Get(std::string url, std::map<std::string, std::string>& headers);
		void Get(std::string url, std::function<void (int status, std::map<std::string, std::string>& headers, std::string body)> callback);
		void Get(std::string url, std::function<void (int status, std::string body)> callback);
		void Get(std::string url, std::function<void (std::string body)> callback);

		std::string Post(std::string url, std::string data);
		std::string Post(std::string url, std::string data, std::map<std::string, std::string>& headers);
		void Post(std::string url, std::string data, std::function<void (int status, std::map<std::string, std::string>& headers, std::string body)> callback);
		void Post(std::string url, std::string data, std::function<void (int status, std::string body)> callback);
		void Post(std::string url, std::string data, std::function<void (std::string body)> callback);
	}
}