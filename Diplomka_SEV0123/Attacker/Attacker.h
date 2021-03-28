#pragma once
#include "stdafx.h"



class Attacker
{
public:
	void set_target(std::filesystem::path p);
	void execute_payload();
	void execute_exe();
private:
	std::filesystem::path target_file;
};