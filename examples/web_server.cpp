#include <iostream>
#include <socialite>

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