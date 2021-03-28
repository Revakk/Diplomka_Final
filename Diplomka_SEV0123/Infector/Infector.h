#pragma once
#include "stdafx.h"

class Infector
{
public:
	Infector(int f) : number_of_files(f) {};

	void files_to_infect();
	std::filesystem::path get_path_by_index(int index);
	bool file_already_running(std::filesystem::path p);
private:
	bool file_exists(std::filesystem::path p);
	void create_file(std::filesystem::path p);
	void get_exes(std::vector<std::filesystem::path>& dir_paths, std::vector<std::pair<std::filesystem::path, int>>& exe_paths);
	std::string get_exe_name(const std::filesystem::path& p) const;

	int number_of_files = 0;
	std::vector<std::pair<std::filesystem::path, int>> infected_files;

};