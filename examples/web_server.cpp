#include <iostream>
#include <socialite>

int main() {
	Socialite::Web::Server webServer;

	webServer.run();

	std::cout << "press enter to end the server\n";
	std::string str;
	std::cin >> str;
	return 0;
}