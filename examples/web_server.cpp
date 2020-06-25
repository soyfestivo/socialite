#include <iostream>
#include <socialite>
#include <json/json.h>

class CustomServer : public Socialite::Web::Server {
	private:

	public:
	std::string serverAPI(HttpHeader* header, HttpResponseHeader* rHeader, std::string ip, std::smatch matcher, bool* success) {
		*success = false;

		if(header->URI == "/api/cool-cpp-served-content") {
			*success = true;
			return "<b><center>C++ to the rescue!</center></b>\n";
		}

		return "";
	}
	
	virtual Json::Value attemptJwtSignIn(std::string username, std::string password) {
		if(username == "stephen" && password == "password") {
			Json::Value root;
			root["username"] = "stephen";
			root["email"] = "stephen@localhost";
			return root;
		}
		else {
			throw -1;
		}
	}
};

int main() {
	CustomServer webServer;

	webServer.run();

	try {
		std::cout << "press enter to end the server\n";
		std::string str;
		do {
			std::cin.clear();
		} while(!(std::cin >> str) && str != "Shutdown");
	}
	catch(int e) {
		std::cout << e << "Error thrown\n";
	}
	return 0;
}