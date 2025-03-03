
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <thread>
#include <chrono>
#include <map>
#include <memory>

#define PROCCESS_NAME "cs.exe"
#define CLIENT "client.dll"
#define HW "hw.dll"

namespace offset {
    constexpr uintptr_t on_ground_offset = 0x122E2D4;
    constexpr uintptr_t jump_offset = 0x131434;
    constexpr uintptr_t incrosshair_offset = 0x125314;
    constexpr uintptr_t m_dwPunchAngles = 0x122E324;
};
namespace utils
{
    template <typename T>
    constexpr void write_process_memory(HANDLE process, const std::uintptr_t& address, const T& value) noexcept {
        WriteProcessMemory(process, reinterpret_cast<void*>(address), &value, sizeof(T), NULL);
    }

    template <typename T>
    constexpr const T read_process_memory(HANDLE process, const std::uintptr_t& address) noexcept {
        T value = { };
        ReadProcessMemory(process, reinterpret_cast<const void*>(address), &value, sizeof(T), NULL);
        return value;
    }

     DWORD get_process_id(const char* process_name) {
        DWORD processId = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 processEntry;
            processEntry.dwSize = sizeof(PROCESSENTRY32);

            if (Process32First(snapshot, &processEntry)) {
                do {
                    if (_stricmp(processEntry.szExeFile, process_name) == 0) {
                        processId = processEntry.th32ProcessID;
                        break;
                    }
                } while (Process32Next(snapshot, &processEntry));
            }
	    CloseHandle(snapshot);
	}
        return processId;
    }
     uintptr_t get_module_base_address(DWORD process_id, const char* module_name) {
        uintptr_t moduleBaseAddress = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
        if (snapshot != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 moduleEntry;
            moduleEntry.dwSize = sizeof(MODULEENTRY32);

            if (Module32First(snapshot, &moduleEntry)) {
                do {
                    if (_stricmp(moduleEntry.szModule, module_name) == 0) {
                        moduleBaseAddress = (uintptr_t)moduleEntry.modBaseAddr;
                        break;
                    }
                } while (Module32Next(snapshot, &moduleEntry));
            }
            CloseHandle(snapshot);
        }
        return moduleBaseAddress;
    }
}

class processModules
{
public:
	processModules(const char* processName, const char* clientModuleName, const char* hwModuleName)
	{
		process_id = utils::get_process_id(processName);
		if(!process_id) throw std::runtime_error("Invalid processID");
		process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
	   	if(!process) throw std::runtime_error("Invalid processHANDLE");
		client_dll = utils::get_module_base_address(process_id, clientModuleName);
		if(!client_dll) throw std::runtime_error("Invalid client_dll");
		hw_dll = utils::get_module_base_address(process_id, hwModuleName);
		if(!hw_dll) throw std::runtime_error("Invalid hw_dll");	
	}
	~processModules()
	{
		if(process)
			CloseHandle(process);
	}

	uintptr_t& getClientModuleBaseAddress(){return client_dll;}
    uintptr_t& getHwModuleBaseAddress() {return hw_dll;}
	DWORD getProcessId(){return process_id;}
	HANDLE& getProcessHandle(){return process;}

private:
	uintptr_t client_dll = 0;
	uintptr_t hw_dll = 0;
	DWORD process_id = 0;
	HANDLE process = nullptr;

}*processModules_t = new processModules(PROCCESS_NAME, CLIENT, HW);

class cheatBase 
{
public:
    virtual void _exec() = 0;
    ~cheatBase() = default;
};
class triggerBot : public cheatBase
{
public:
    triggerBot(const uint32_t& incrosshair) : incrosshair(incrosshair)
    {}

    void __thiscall _set(const uint32_t& incrosshair_new) { incrosshair = incrosshair_new;}

	void _exec() override
    {
        if(incrosshair == 0x02)
        {
            INPUT input = { 0 };
            input.type = INPUT_MOUSE;
            input.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
            SendInput(1, &input, sizeof(INPUT));

            input.mi.dwFlags = MOUSEEVENTF_LEFTUP;
            SendInput(1, &input, sizeof(INPUT));
        }
    }
private:
    uint32_t incrosshair;
};
class bhop : public cheatBase
{
public:
    bhop(const uint32_t& on_ground, HANDLE& process, uintptr_t& client_dll) :
        on_ground(on_ground), process(process), client_dll(client_dll) {}

    void __thiscall _set(const uint32_t& on_ground_new) { on_ground = on_ground_new; }

    void _exec() override
    {
        if (GetAsyncKeyState(0x20))
        {
            on_ground ? utils::write_process_memory<int>(process, client_dll + offset::jump_offset, 5) :
                        utils::write_process_memory(process, client_dll + offset::jump_offset, 4);
        }
    }
private:
    uint32_t on_ground;
    HANDLE process;
    uintptr_t client_dll;
};

class cheatManager
{
public:
    cheatManager() : 	bhop_t(std::make_unique<bhop>(0, processModules_t->getProcessHandle(), processModules_t->getClientModuleBaseAddress())),
						triggerbot_t(std::make_unique<triggerBot>(0)){}
    void _execAll()
    {
        bhop_t->_exec();
        triggerbot_t->_exec();
    }
    void _setAll()
    {
        bhop_t->_set(utils::read_process_memory<uint32_t>(processModules_t->getProcessHandle(), processModules_t->getHwModuleBaseAddress() + offset::on_ground_offset));
        triggerbot_t->_set(utils::read_process_memory<uint32_t>(processModules_t->getProcessHandle(), processModules_t->getClientModuleBaseAddress() + offset::incrosshair_offset));
    }
private:
    std::unique_ptr<bhop> bhop_t;
    std::unique_ptr<triggerBot> triggerbot_t;
}cheatManager_t;

bool rd_running = true;

DWORD WINAPI _readMemory_T(LPVOID lp)
{
    while (rd_running)
    {
        cheatManager_t._setAll();
        Sleep(10);
    }
    std::cout << "\n[rd mem stop]";
    return 0;
}
HANDLE WINAPI startReadMemory_T(HANDLE& process)
{
    HANDLE hThread = CreateThread(
        NULL,
        0,
        _readMemory_T,
        process,
        0,
        NULL
    );

    if (hThread == NULL) {
        std::cerr << "[Error create thread!]" << std::endl;
    }
    return hThread;
}

inline void WINAPI endRMemory_T(HANDLE& hThreadRead)
{
    if (hThreadRead) {
        rd_running = false;

        WaitForSingleObject(hThreadRead, INFINITE);
        CloseHandle(hThreadRead);
    }
}
inline void simLoadProcess() 
{
    const char loadingSymbols[] = { '/','-' ,'\\','|' };
    char welcomeBar [] = { "[Loading]\n*[Done]\n[Welcome!]\n[bhop-triggerBot] > [Active]\n[Exit] > [F6]" };

    const int SIZE = sizeof(loadingSymbols) / sizeof(loadingSymbols[0]);

    for (char* i = welcomeBar; *(i) != '\0'; i++)
    {
        if(*i == '*')
        {
            for (int i = 0; i < 20; ++i)
            {
                std::cout << loadingSymbols[i % SIZE] << "\r";
                std::cout.flush();
                Sleep(100);
            }
            continue;
        }
        if (*i == '>')
        {
            (*i) = 0x10;
        }
        std::cout << *i;
        Sleep(100);
    }
}

inline bool _RUN() 
{
	simLoadProcess();
        HANDLE hReadThread = startReadMemory_T(processModules_t->getProcessHandle());
        while (true) 
        {
        	if (GetAsyncKeyState(0x75)) { break; }
        	cheatManager_t._execAll();
        	Sleep(1);
        }
		endRMemory_T(hReadThread);
		delete processModules_t;
		return 0;

    std::cout << "[Please, run cs 1.6!]" << '\n';
    return 0;
}

int main()
{
    if(!_RUN()) return EXIT_SUCCESS;
}
