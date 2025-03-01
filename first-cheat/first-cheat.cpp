﻿
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <thread>
#include <chrono>
#include <map>

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

    template <typename T>
    constexpr void readFrequencyСontrol(T &pTime)
    {
        auto cTime = std::chrono::steady_clock::now();

        auto elapsedTime = std::chrono::duration_cast<std::chrono::milliseconds>(cTime - pTime).count();

        const int desiredRefreshRate = 60;
        const int frameTime = 1000 / desiredRefreshRate;

        if (elapsedTime < frameTime) {
            std::this_thread::sleep_for(std::chrono::milliseconds(frameTime - elapsedTime));
        }
        pTime = std::chrono::steady_clock::now();
    }
    template <typename T>
    constexpr void writeFrequencyСontrol(T& pTime)
    {
        auto cTime = std::chrono::steady_clock::now();

        auto elapsedTime = std::chrono::duration_cast<std::chrono::milliseconds>(cTime - pTime).count();

        const int desiredRefreshRate = 60;
        const int frameTime = 1000 / desiredRefreshRate;

        if (elapsedTime < frameTime) {
            std::this_thread::sleep_for(std::chrono::milliseconds(frameTime - elapsedTime));
        }
        pTime = std::chrono::steady_clock::now();
    }
}


//struct modules 
//{
//    modules() : client_dll(utils::get_module_base_address(process_id, CLIENT)),
//                hw_dll(utils::get_module_base_address(process_id, HW)) {}
//private:
//    uintptr_t client_dll;
//    uintptr_t hw_dll;
//}modules_t;

DWORD process_id = utils::get_process_id(PROCCESS_NAME);
    uintptr_t client_dll = utils::get_module_base_address(process_id, CLIENT);
        uintptr_t hw_dll = utils::get_module_base_address(process_id, HW);
            HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);

class cheatBase 
{
public:
    virtual void _exec() = 0;
    ~cheatBase() = default;
};
class triggerBot : public cheatBase
{
public:
    triggerBot(const uint32_t& incrosshair) : incrosshair(incrosshair) {}

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
        on_ground(on_ground), process(process), client_dll(client_dll) {
    }

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
    HANDLE& process;
    uintptr_t& client_dll;
};

bool rwrd_running = true;

bhop bhop_t(0, process, client_dll);
    triggerBot triggerbot_t(0);

DWORD WINAPI _readMemory_T(LPVOID lp)
{
    while (rwrd_running)
    {
        bhop_t._set(utils::read_process_memory<uint32_t>(process, hw_dll + offset::on_ground_offset));
        triggerbot_t._set(utils::read_process_memory<uint32_t>(process, client_dll + offset::incrosshair_offset));
        Sleep(10);
    }
    std::cout << "\nrd mem lock";
    return 0;
}

HANDLE startReadMemory_T(HANDLE& process)
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
        std::cerr << "Не удалось создать поток чтения памяти!" << std::endl;
    }
    return hThread;
}

void endRWMemory_T(HANDLE& hThreadRead)
{
    if (hThreadRead) {
        rwrd_running = false;

        WaitForSingleObject(hThreadRead, INFINITE);
        CloseHandle(hThreadRead);
    }
}

inline bool _RUN() 
{
    if (process_id)
    {
        if (client_dll)
        {
            if (hw_dll)
            {
                if (process)
                {   
                    char arr[] = { "[Welcome!]\n[bhop-triggerBot] > [Active]\n[Exit] > [F6]" };

                    for(char* i = arr; *(i) != '\0'; i++)
                    {
                        if(*i == '>')
                        {
                            (*i) = 0x10;
                        }
                        std::cout << *i;
                        Sleep(5);
                    }

                    HANDLE hReadThread = startReadMemory_T(process);

                    while (true) 
                    {
                        if (GetAsyncKeyState(0x75)) { break; }

                            bhop_t._exec();
                            triggerbot_t._exec();

                        Sleep(1);
                    }
                    endRWMemory_T(hReadThread);
                    return 0;
                }
            }
        }
    }
    else
    {
        std::cout << "[Please, run cs 1.6!]" << '\n';
        return 0;
    }
        
}

int main()
{
    if(!_RUN()) return EXIT_SUCCESS;
}