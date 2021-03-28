#include "stdafx.h"


int main ()
{
	boost::asio::io_context io_context;
	Client::Client c("nn.txt", "127.0.0.1", 1234, io_context);



	return 0;
}