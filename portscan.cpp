/*
	Preston Mitchell
	11091132
	Computer Security - Hoffman - 4550
	12/5/18
	
	This program is a very simple port scanner
*/
#include <iostream>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>
#include <sys/types.h> 
#include <sys/socket.h>
#include <algorithm>
#include <fstream>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <cstring> 
#include <fcntl.h>
#include <sstream>

using namespace std;

void portparser(string portlist, vector<int> &ports)
{
	
	string commadelim = ",";
	string hyphendelim = "-";
	
	int min = 0;
	int max = 0;
	int temp = 0;
	//string token = portlist.substr(0, portlist.find(hyphendelim);
	//string token2 = portlist.substr(portlist.find(hyphendelim), 
	size_t hyphenfound = portlist.find(hyphendelim);
	size_t commafound = portlist.find(commadelim);

	size_t pos = 0;
	
	string token;
	if(hyphenfound != string::npos)
	{
		while((pos = portlist.find(hyphendelim)) != string::npos) //lots of vector find function black magic
		{
			token = portlist.substr(0,pos); //nab the start of the list
			//cout << "This is our token: " << token << endl;
			portlist.erase(0, pos + hyphendelim.length());
			
		}
		//cout << "remaining port: " << portlist << endl;
		
		min = stoi(token);
		max = stoi(portlist); //because of the erase, the only thing left in portlist is the final num
		
		ports.clear();
		
		for(int i = min; i <= max; i++) //ez increment
		{
			ports.push_back(i);
		}
	}
	else if (commafound != string::npos)
	{
		ports.clear();
		
		while((pos = portlist.find(commadelim)) != string::npos)
		{
			token = portlist.substr(0,pos);
			//cout << "This is our token: " << token << endl;
			temp = stoi(token);
			ports.push_back(temp);
			
			portlist.erase(0, pos + commadelim.length());
			
		}
		//cout << "remaining port: " << portlist << endl;
		temp = stoi(portlist);
		ports.push_back(temp);
		
	}	
	else if(commafound == string::npos && hyphenfound == string::npos)
	{
		//cout << "Did we get here?" << endl;
		ports.clear();
		temp = stoi(portlist);
		ports.push_back(temp);
	}
}






void ipparser(string iplist, vector<string> &iptable)
{
	
	string commadelim = ",";
	string hyphendelim = "-";
	
	//string token = portlist.substr(0, portlist.find(hyphendelim);
	//string token2 = portlist.substr(portlist.find(hyphendelim), 
	size_t hyphenfound = iplist.find(hyphendelim);
	size_t commafound = iplist.find(commadelim);

	size_t pos = 0;
	
	string token;
	if(commafound != string::npos) //Basically if we find the list then do this
	{
		while((pos = iplist.find(commadelim)) != string::npos)
		{
			token = iplist.substr(0,pos);
			//cout << "This is our token: " << token << endl;
			iplist.erase(0, pos + commadelim.length());
			iptable.push_back(token);
		}
		//cout << "IP list: " << iplist << endl;
		iptable.push_back(iplist);
		
	}
	else if (hyphenfound != string::npos)
	{
		int a = 0, b = 0, c = 0, d = 0, e = 0;
		string ipaddress, part1, part2, part3, part4;
		stringstream s(iplist);
		char ch, hy;
		s >> a >> ch >> b >> ch >> c >> ch >> d >> hy >> e;
		
		for(int i = d; i <= e; i++)
		{
			//cout << "Testing: " << a << ch << b << ch << c << ch << i << endl;
			part1 = to_string(a); //This is SUPER hacky but I was on a time crunch.
			part2 = to_string(b);
			part3 = to_string(c);
			part4 = to_string(i);
			ipaddress.append(part1);
			ipaddress.append(".");
			ipaddress.append(part2);
			ipaddress.append(".");
			ipaddress.append(part3);
			ipaddress.append(".");
			ipaddress.append(part4);
			//cout << "Ip address test: " << ipaddress << endl;
			iptable.push_back(ipaddress);
			ipaddress.clear();
		}
		
		
	}
	else if (commafound == string::npos && hyphenfound == string::npos)
	{
		iptable.push_back(iplist);
	}
	
}




int main(int argc, char **argv)
{
	vector<string> commands(argv + 1, argv + argc); //puts everything in the command line into a vector for ez parsing
	vector<string> iptable;
	string line;
	
	vector<int> ports;
	string ip;
	int portindex;
	bool TCP = true;
	bool UDP = true;
	
	for(int i = 1; i<1025; i++)
	{
		ports.push_back(i);
	}
	
	
	/*for(int i=0; i<commands.size(); ++i)
		cout << commands[i] << endl;
	/*for(int i=0; i<ports.size(); ++i)
		cout << ports[i] << ' ';
	*/
	
	if (std::find(commands.begin(), commands.end(), "--port") != commands.end())
	{
		//cout << "Found the port flag!" << endl;
		vector<string>::iterator it = find(commands.begin(), commands.end(), "--port");
		int index = distance(commands.begin(), it);
		//cout << "Port number index is : " << index;
		//cout << "Port numbers are: " << commands[index + 1] << endl;
		portparser(commands[index + 1], ports);		//send whatever is after the port flag to the port parser since it should always be the numbers but meh
	}
	
	
	
	if (std::find(commands.begin(), commands.end(), "--help") != commands.end())
	{
		//cout << "Found the help flag!" << endl;
		
		//cout << "You must 
		cout << "Available options are: --port, --help, --file, and --transport" << endl;
		cout << "Usage: put --port on the command line followed by a space and either a single port number (22), a hyphenated list of ports (10-30), or a comma seperated list of ports (22,23,24,67,89)" << endl;
		cout << "Usage: put --ip on the command line followed by a space and either a single ip address (127.1.1.1), a hyphenated list of ips (127.1.1.1-5), or a comma seperated list of ips (127.1.1.1,1.1.1.1,2.2.2.2)" << endl;
		cout << "Usage: put --file on the command line followed by a space and the name of the file with the extension (ipfile.txt)" << endl;
		cout << "Usage: --transport flag doesnt work but it gets found so...." << endl;
		cout << "Note: I did not mess with the timeout so it takes a bit to return things. Sorry. Using 127.1.1.1 works quickly though if you require it." << endl;
		//cout << "Usage: put --transport on the command line followed by a space and the name of the 
		//Need to finish help but its tedious
	}
	
	
	if (std::find(commands.begin(), commands.end(), "--ip") != commands.end())
	{
		//cout << "Found the ip flag!" << endl;
		vector<string>::iterator it = find(commands.begin(), commands.end(), "--ip");
		int index = distance(commands.begin(), it);
		
		//Validate the IP and if it is more than one, put it all in. For now we do it like this for testing.
		ipparser(commands[index + 1], iptable); //get whatever is right after the --ip flag and parse it for either a single ip, a comma list, or a hyphen list
		
		
		//iptable.push_back(commands[index+1]);
	}
	
	
	
	
	if (std::find(commands.begin(), commands.end(), "--file") != commands.end())
	{
		//cout << "Found the file flag!" << endl;
		vector<string>::iterator it = find(commands.begin(), commands.end(), "--file");
		int index = distance(commands.begin(), it);
		
		
		string file = commands[index+1];
		ifstream ipfile(file.c_str());
		
		while(getline(ipfile, line))
		{
			iptable.push_back(line);
		}	
	} //Basically if it finds the file, we getline each line and upload it to our ip vector
	
	
	if (std::find(commands.begin(), commands.end(), "--transport") != commands.end())
	{
		cout << "Found the transport flag!" << endl;
		if (std::find(commands.begin(), commands.end(), "TCP") != commands.end())
		{
			UDP = false;
		}
		if (std::find(commands.begin(), commands.end(), "tcp") != commands.end())
		{
			UDP = false;
		}
		
		if (std::find(commands.begin(), commands.end(), "UDP") != commands.end())
		{
			TCP = false;
		}
		if (std::find(commands.begin(), commands.end(), "udp") != commands.end())
		{
			TCP = false;
		}

	} //This does nothing
	
	//cout << "TCP - " << TCP << endl;
	//cout << "UDP - " << UDP << endl;
	
	/*
	Right here is where we will be parsing the input to see what flags if any are given and what we are going to do with them. Port will change the port vector, etc.
	*/
	/*for(int i=0; i<ports.size(); ++i)
		cout << ports[i] << ' ';
	
	for(int i = 0; i < iptable.size(); ++i)
		cout << iptable[i] << endl;
	*/ //print functions for error testing 
	//cout << "The IP address is: " << ip << endl;
	//We need to make a function to validate the IP address. Then we need to put in a check in that function that checks to see if the IP is a solo one or a hypenated list of IPS. To check for the hyphen
	//we will need to make a function similar to the port parser
	
	
	
	int sockfd = 0, n = 0;

	struct sockaddr_in serv_addr;
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("socket error\n");
		exit(EXIT_FAILURE);
	}
 
 	cout << "IP             Port          Status         Service" << endl;
	for(int i = 0; i < iptable.size(); i++)
	{
		
		const char* c = iptable[i].c_str();

		
		for(int k = 0; k < ports.size(); k++)
		{
			
			
				struct sockaddr_in address; 
				int sock = 0, valread, valopt; 
				struct sockaddr_in serv_addr; 
				struct servent * service;
				string name;
		
				if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) //Oh sockets how ive missed ye
				{ 
					printf("\n Socket creation error \n"); 
					return -1; 
				} 
		
				memset(&serv_addr, '0', sizeof(serv_addr)); 
			   
				serv_addr.sin_family = AF_INET; 
				serv_addr.sin_port = htons(ports[k]); 
				   
				if(inet_pton(AF_INET, c, &serv_addr.sin_addr)<=0)  
				{ 
					printf("\nInvalid address\n"); 
					return -1; 
				} 
				service = getservbyport(htons(ports[k]),"tcp");
			   	
				if(!service) //This screwed me over so bad. But it works now. 
				{
					name = "Unknown service";
				}
				else
				{
					name = service->s_name; //Get the actual service name or attempt to
				}
								
				if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) //connection
				{ 
					cout << iptable[i] << "       " << ports[k] << "             Closed" << "              " << name << endl;	 //Bad formatting but meh
					//cout << "Port Closed"; 
				}
				else
				{
					//cout << "IP             Port          Status         Service" << endl;
					cout << iptable[i] << "        " << ports[k] << "            Open" << "             " << name << endl;	
				}				
				
				close(sock); //gotta close or we have way to many sockets open on default which screws it up so bad
		}

	}
	
	return 0;
}