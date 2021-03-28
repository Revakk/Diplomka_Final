#pragma once
#include "stdafx.h"


class Attacker
{
public:
	Attacker(std::filesystem::path p);
	void set_target(std::filesystem::path p);
	void execute_payload();
	void execute_exe();
private:
	std::filesystem::path file_name;
};