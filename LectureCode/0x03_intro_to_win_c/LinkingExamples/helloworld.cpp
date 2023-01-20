#include <iostream>
#include <string> 

using namespace std;

int main(){
	cout << "Greetings! What should I call you?" << endl;
	string name; 
	getline(cin, name);
	cout << "Hello there "<< name << endl;
	return 0;
}

