#include <iostream>
#include <unistd.h>

using namespace std;

int main(int argc, char *argv[])
{
	if(argc != 2)
	{
		cout<<"Wrong number of arguments\n";
		return 0;
	}
	string a = argv[1];
	cout<<a<<endl;
	return 0;
}
