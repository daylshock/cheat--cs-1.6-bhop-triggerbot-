
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
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
	processModules(const char* PROCESS_NAME, const char* CLIENT_MODULE_NAME, const char* HW_MODULE_NAME)
	{
		processId = utils::get_process_id(PROCESS_NAME);
		if(!processId) 
            throw std::runtime_error("Invalid processID");
		processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	   	if(!processHandle)
            throw std::runtime_error("Invalid processHANDLE");
		clientDll = utils::get_module_base_address(processId, CLIENT_MODULE_NAME);
		if(!clientDll)
            throw std::runtime_error("Invalid client_dll");
		hwDll = utils::get_module_base_address(processId, HW_MODULE_NAME);
		if(!hwDll)
            throw std::runtime_error("Invalid hw_dll");	
	}
	~processModules()
	{
		if(processHandle)
			CloseHandle(processHandle);
	}
	uintptr_t& getClientModuleBaseAddress(){return clientDll;}
    uintptr_t& getHwModuleBaseAddress(){return hwDll;}
	DWORD getProcessId(){return processId;}
	HANDLE& getProcessHandle(){return processHandle;}

private:
	uintptr_t clientDll = 0;
	uintptr_t hwDll = 0;
	DWORD processId = 0;
	HANDLE processHandle = nullptr;

}*processModules_t = new processModules(PROCCESS_NAME, CLIENT, HW);

class cheatBase 
{
public:
    virtual void exec() = 0;
    ~cheatBase() = default;
};
class triggerBot : public cheatBase
{
public:
    triggerBot() {}
    void __thiscall set(const uint32_t& INCROSSHAIR_NEW) { incrosshair = INCROSSHAIR_NEW; }

	void exec() override
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
    uint32_t incrosshair = 0;
};
class bhop : public cheatBase
{
public:
    bhop(HANDLE& process, uintptr_t& client_dll) :
        on_ground(on_ground), process(process), client_dll(client_dll) {}

    void __thiscall set(const uint32_t& ON_GROUND_NEW) { on_ground = ON_GROUND_NEW; }

    void exec() override
    {
        if (GetAsyncKeyState(0x20))
        {
            on_ground ? utils::write_process_memory<int>(process, client_dll + offset::jump_offset, 5) :
                        utils::write_process_memory(process, client_dll + offset::jump_offset, 4);
        }
    }
private:
    uint32_t on_ground = 0;
    HANDLE process;
    uintptr_t client_dll;
};

class cheatManager
{
public:
    cheatManager() : 	bhop_t(std::make_unique<bhop>(processModules_t->getProcessHandle(), processModules_t->getClientModuleBaseAddress())),
						triggerbot_t(std::make_unique<triggerBot>()){}
    void execAll()
    {
        bhop_t->exec();
        triggerbot_t->exec();
    }
    void setAll()
    {
        bhop_t->set(utils::read_process_memory<uint32_t>(processModules_t->getProcessHandle(), processModules_t->getHwModuleBaseAddress() + offset::on_ground_offset));
        triggerbot_t->set(utils::read_process_memory<uint32_t>(processModules_t->getProcessHandle(), processModules_t->getClientModuleBaseAddress() + offset::incrosshair_offset));
    }
private:
    std::unique_ptr<bhop> bhop_t;
    std::unique_ptr<triggerBot> triggerbot_t;
}cheatManager_t;

bool running = true;

DWORD WINAPI readMemory(LPVOID lp)
{
    while (running)
    {
        cheatManager_t.setAll();
        Sleep(10);
    }
    std::cout << "\n[rd mem stop]";
    return 0;
}
HANDLE WINAPI startThreadReadMemory(HANDLE& process)
{
    HANDLE threadRead = CreateThread(
        NULL,
        0,
        readMemory,
        process,
        0,
        NULL
    );
    if (threadRead == NULL) {
        std::cerr << "[Error create thread!]" << std::endl;
    }
    return threadRead;
}

inline void WINAPI stopReadMemory(HANDLE& ThreadRead)
{
    if (ThreadRead) {
        running = false;
        WaitForSingleObject(ThreadRead, INFINITE);
        CloseHandle(ThreadRead);
    }
}
inline void simLoadProcess() 
{
    const char LOADING_SYMBOLS[] = { '/','-' ,'\\','|' };
    char welcomeBar[] = { "[Loading]\n*[Done]\n[Welcome!]\n[bhop-triggerBot] > [Active]\n[Exit] > [F6]" };

    const int SIZE_ARRY_LOADING_SYMBOLS = sizeof(LOADING_SYMBOLS) / sizeof(LOADING_SYMBOLS[0]);
    
    for (char* i = welcomeBar; *(i) != '\0'; i++)
    {
        if(*i == '*')
        {
            for (int i = 0; i < 20; ++i)
            {
                std::cout << LOADING_SYMBOLS[i % SIZE_ARRY_LOADING_SYMBOLS] << "\r";
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

inline bool runCheat() 
{
	simLoadProcess();
    HANDLE threadRead = startThreadReadMemory(processModules_t->getProcessHandle());
    while (true) 
    {
        if (GetAsyncKeyState(0x75)) { break; }
        cheatManager_t.execAll();
        Sleep(1);
    }
		stopReadMemory(threadRead);
		delete processModules_t;
		return 0;
    std::cout << "[Please, run cs 1.6!]" << '\n';
    return 0;
}

int main()
{
    if(!runCheat()) return EXIT_SUCCESS;
}
