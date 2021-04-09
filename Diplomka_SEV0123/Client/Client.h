#pragma once
#include "stdafx.h"

using namespace boost::asio;
using ip::tcp;
using std::string;
using std::cout;
using std::endl;


namespace Client
{
    class Client
    {
    private:
        std::string filename;
        bool attack = false;
        std::string attack_file = "attack_file";
        boost::asio::io_context& io_context;
        boost::asio::ip::address server_ip;
        std::uint16_t server_port;
        tcp::socket socket;
        std::string msg_from_client = "";
    public:
        Client(std::string filename, std::string ip_address, std::uint16_t port, boost::asio::io_context& io);
        void set_msg(std::string&& mess);
        void write_to_server();
        void read_from_server();
        std::string get_attack_command();
    };
}
