#include <iostream>
#include <socialite>

int main() {
	std::string url;
	std::cout << "URL: ";
	std::cin >> url;

	std::cout << Socialite::Web::Get(url) << "\n";
}