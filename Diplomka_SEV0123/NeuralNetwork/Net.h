#pragma once
#include <vector>
#include "Connection.h"
#include <string>
#include <filesystem>


typedef std::vector<Neuron> Layer;


class Net
{
public:
	Net(unsigned int, std::vector<unsigned int>, unsigned int);
	Net(std::string&);
	Net(std::filesystem::path);
	void construct_net(unsigned int&, std::vector<unsigned int>&, unsigned int&);
	void update_values(std::string&&);
	void set_connections();
	void feed_forward(std::vector<double>&);
	void back_propagation(std::vector<double>&);
	void get_results(std::vector<double>&);
	double get_result();
	std::vector<Layer> net;
	std::vector<std::vector<Connection>> connections;
private:
	double gradient = 0.0;
	int values_from_string(std::string&&, std::string_view);
	template<typename T>
	void values_from_string(std::string&&, std::string&, std::vector<T>&);
	double error;
	//std::vector<Layer> net;
	unsigned int number_of_hidden_layers;
};