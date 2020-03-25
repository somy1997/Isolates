#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

using namespace std;
int main()
{
	string value, s; // declaration
	s = getenv("QUERY_STRING"); // s stores the query string extracted from URL	
	cout<<"content-type: text/html"<<endl<<endl;
	cout<<"<h1>CGI C++ example</h1>"<<endl;
	cout<<"<p>";
	cout<<s<<endl;
	string comm = "/home/nbs/Desktop/cgi_controller/inout/test " + s;
	cout<<comm<<endl;
	int err = system(comm.c_str());
	cout<<"err = "<<err;
	cout<<"</p>"<<endl;
//	sleep(2);
	return 0;
}
