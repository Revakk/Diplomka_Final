#include "stdafx.h"


int main ()
{
	io_context io_c;

	Client::Client c("Neural_net.txt","127.0.0.1",1234,io_c);
	c.set_msg("attack");
	c.write_to_server();
	c.read_from_server();


	//Sleep(5000);
	//Net my_net("Neural_net.txt");


	/*
	Infector inf(0);
	inf.infect_specific_file("E:/Users/Jan/PE/Project2.exe",0);

	Attacker att("E:/Users/Jan/PE/Project2.exe");
	att.execute_payload();*/
	return 0;
}