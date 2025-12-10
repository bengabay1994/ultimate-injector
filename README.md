# UltimateInjector

UltimateInjector is a powerful and flexible DLL injection tool designed for Windows. It provides a command-line interface to inject and uninject DLLs into target processes.

## Getting Started

To get started with UltimateInjector, you can download the latest compiled executable from the [Releases](../../releases) page.

1.  Go to the **Releases** page of this repository.
2.  Download the `UltInjector.exe` file from the latest release. or `UltInjector_x86.exe` for 32-bit processes/systems.

## Usage

UltimateInjector is a command-line tool. You can view the help menu at any time by running:

```powershell
.\UltInjector.exe --help
```

### Arguments

| Flag | Long Flag | Description | Required |
| :--- | :--- | :--- | :--- |
| `-p` | `--pid` | Target process ID (Decimal or Hex `0x...`). | Yes (or `-P`) |
| `-P` | `--process` | Target process name (or part of it). | Yes (or `-p`) |
| `-d` | `--dll` | Path to the DLL file to inject/uninject. | **Yes** |
| `-u` | `--uninject` | Uninject the DLL from the target process. | Optional |
| `-t` | `--technique` | Injection technique to use (default: `basic`). | Optional |
| `-h` | `--help` | Show the help message. | Optional |
| | `--version` | Show version information. | Optional |

### Examples

**Inject by Process ID (Decimal)**
```powershell
.\UltInjector.exe -p 1234 -d "C:\Path\To\MyDll.dll"
```

**Inject by Process ID (Hex)**
```powershell
.\UltInjector.exe -p 0x4D2 -d "C:\Path\To\MyDll.dll"
```

**Inject by Process Name**
```powershell
.\UltInjector.exe -P notepad -d "C:\Path\To\MyDll.dll"
```

**Uninject a DLL**
```powershell
.\UltInjector.exe -u -P notepad -d "C:\Path\To\MyDll.dll"
```

**Specify Injection Technique**
```powershell
.\UltInjector.exe -P notepad -d "C:\Path\To\MyDll.dll" -t basic
```

## Future Vision

I am constantly working to improve UltimateInjector. In future updates, we plan to support advanced injection techniques including:

*   **Reflective DLL Injection**: Load a DLL from memory without touching the disk.
*   **APC Injection**: Queue an APC to a thread in the target process to execute the injection code.
*   **Thread Hijacking**: Suspend a thread and modify its context to redirect execution.

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Misuse of this software to inject code into processes without permission is illegal. The authors are not responsible for any damages caused by the use of this tool.
