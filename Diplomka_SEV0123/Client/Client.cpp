#include "Client.h"


namespace Client
{
    Client::Client(std::string filename, std::string ip_address, std::uint16_t port, boost::asio::io_context& io) :
        filename(filename), server_ip(boost::asio::ip::address::from_string(ip_address)), server_port(port), io_context(io), socket(io_context)
    {
        socket.connect(tcp::endpoint(server_ip, server_port));
    }

    void Client::write_to_server()
    {
        boost::system::error_code err;
        boost::asio::write(socket, boost::asio::buffer(msg_from_client), err);
        if (!err)
        {
            std::cout << "Message sent succesfully!" << std::endl;
        }
        else
        {
            cout << "send failed, error message:" << err.message() << endl;
        }

    }

    void Client::set_msg(std::string&& msg)
    {
        msg_from_client = std::move(msg);
    }

    void Client::read_from_server()
    {
        boost::system::error_code err;
        boost::asio::streambuf receive_buffer;

        boost::asio::read(socket, receive_buffer, boost::asio::transfer_all(), err);

        std::ofstream output_file(filename);

        if (!output_file)
        {
            std::cout << "error opening file";
        }
        output_file.clear();

        if (err && err != boost::asio::error::eof) {
            cout << "Listening failed, error message: " << err.message() << endl;
        }
        else {
            std::string data = boost::asio::buffer_cast<const char*>(receive_buffer.data());
            // const char* data = boost::asio::buffer_cast<const char*>(receive_buffer.data());
            cout << data << endl;
            output_file << data;
        }
        output_file.close();
    }
}
//
//
//int main() {
//    boost::asio::io_context io_context;
//    Client c("nn.txt", "127.0.0.1", 1234, io_context);
//    c.write_to_server();
//    c.read_from_server();
//
//
//    return 0;
//}
