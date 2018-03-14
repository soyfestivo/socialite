#include <iostream>
#include <socialite>

int main() {
	Socialite::Server server(5000, 5, S_DEFAULT);

	server.run();

	std::cout << "press enter to end the server\n";
	std::string str;
	std::cin >> str;
	return 0;
}