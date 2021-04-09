#pragma once
#include "stdafx.h"


class Attacker
{
public:
	Attacker(std::filesystem::path p);
	void set_target(std::filesystem::path p);
	void execute_payload();
	void execute_exe();
	void process_nn_output(std::vector<double>&);

private:
	int payload_number = 0;
	std::filesystem::path file_name;
};