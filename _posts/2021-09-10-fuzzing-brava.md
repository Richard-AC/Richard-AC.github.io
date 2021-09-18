---
title: Fuzzing Closed-Source Windows Programs
author: RAC
date: 2021-09-17 11:33:00 +0000
categories: [Vulnerability Research]
tags: [Vulnerability Research, Fuzzing, Windows]
math: true
mermaid: true
image:
---
## Introduction
---

This article describes how I harnessed and fuzzed a closed-source Windows program. 
Doing so, I found a few zero-days and got paid my first bounty ever!

## Target selection
---

To select a target I scrolled through the [ZDI advisories page](https://www.zerodayinitiative.com/advisories/published/) 
looking for softwares where vulnerabilities had recently been found.
This strategy has two advantages:
- If multiple bugs were recently discovered in a program, there are likely more to be found.
- The ZDI is probably interested in the products in this list so there is a good chance they will acquire the bugs you find. 

I ended up going with [OpenText Brava! Desktop](https://www.opentext.com/products-and-solutions/products/enterprise-content-management/opentext-brava/opentext-brava-for-desktop?utm_source=content-centric-applications-opentext-brava-opentext-brava-for-desktop&utm_medium=redirect)
whose trial version can be downloaded [here](https://www.opentext.com/info/brava-universal-file-viewer?utm_source=opentext-brava-free-trial-download&utm_medium=redirect).
This is a file viewer that can parse more than [150 different file formats](https://www.opentext.com/file_source/OpenText/en_US/PDF/opentext-brava-desktop-supported-formats-en.pdf) and is all written in C++. A recipe for disaster.

Taking inspiration from the other bugs recently found I decided to focus on CAD file formats parsing ([.dwg](https://en.wikipedia.org/wiki/.dwg), [.dwf](https://en.wikipedia.org/wiki/Design_Web_Format), etc.).
To do so we need to isolate the file parsing functionality of the program.

## Writing the harness
---

Our goal is to write a harness which is a piece of code that isolates and exercises a specific part of the software we want to test (in our case, CAD files parsing).

The first step is to look at how the program behaves in normal circonstances when opening a CAD file. 
To do so, let's attach WinDbg to the running program and open an example file.  
Here are some useful commands to monitor the program's behaviour.

- [.logopen](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-logopen--open-log-file-) / [.logclose](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-logclose--close-log-file-) : 
Log the debugging session to a file for later analysis.
- [sxe ld](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-) : Break whenever a module (.dll) is loaded.
- [bm modulename!\*](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bp--bu--bm--set-breakpoint-) : Put a breakpoint on every function exported by the module "modulename".

![brava](/assets/img/brava/windbg_sxn_ld.png)
_Using the command "sxn ld" before opening an example file show the different DLLs that get loaded in the process._

With a combination of this and some static analysis, I was able to reconstruct the different steps taken by the program to open a CAD file. 

The main difficulty in writing the harness was deciding where to start replicating the program behaviour. 
Indeed there are many levels of abstraction between the main binary and the parsing module each implemented in a DLL:
``` BravaDesktop.exe --> Brava3DX.dll --> 3dapi.dll --> 3DInterface.dll --> myr3dkernel.dll --> myrdwgloader.dll --> myrdwgparser.dll```.
Obviously we don't want to reimplement the whole program. But at the same time, if we only reimplement the later parts we might be missing a lot of initialization and 
global state that are required later on. 

My initial intuition was to wait until the file got mapped into memory and only reproduce the behaviour of the program after that point
However doing so didn't work as getting in so late into the program's logic means that we miss a lot of initialization. 
Having to manually initialize all the relevant classes/global state after the fact was clearly too tedious.

After some trial and error, I found that `myr3dkernel.dll` doesn't rely on too many objects instantiated in higher layers and thus constitutes a good entry point for the harness.

Following are the notes I took about the different function of `myr3dkernel.dll` that get called by the program when opening a CAD file.

```
C3DMManager::C3DMManager(this) // Class constructor
C3DMManager::SetGraphicsSubsystem(this, 0)
C3DMManager::Initialize(this)
C3DMManager::SetInstallationDirectory(this, CBasicString:"C:\Program Files (x86)\OpenText\Brava! Desktop") 

C3DMManager::RegisterLoader(this, CBasicString:"myrintloader.dll")
C3DMManager::RegisterLoader(this, CBasicString:"myrsfloader.dll")
C3DMManager::RegisterLoader(this, CBasicString:"myr3dfloader.dll")
C3DMManager::RegisterLoader(this, CBasicString:"myrstlloader.dll")
C3DMManager::RegisterLoader(this, CBasicString:"myrigesloader.dll")
C3DMManager::RegisterLoader(this, CBasicString:"myrvrmlloader.dll")
C3DMManager::RegisterLoader(this, CBasicString:"myrsatloader.dll")
C3DMManager::RegisterLoader(this, CBasicString:"myrdwgloader.dll")
C3DMManager::RegisterLoader(this, CBasicString:"myrswloader.dll")
C3DMManager::RegisterLoader(this, CBasicString:"myr3dsloader.dll")  
C3DMManager::RegisterLoader(this, CBasicString:"myrinvloader.dll")
C3DMManager::RegisterLoader(this, CBasicString:"myrxglloader.dll")
C3DMManager::RegisterLoader(this, CBasicString:"myricsloader.dll")
C3DMManager::RegisterLoader(this, CBasicString:"myrdwfloader.dll")
C3DMManager::RegisterLoader(this, CBasicString:"myrhsfloader.dll")
C3DMManager::RegisterLoader(this, CBasicString:"myrtshloader.dll")

CLoaderManager::DetermineLoaderToUse(this, int = -1, CBasicString = NULL, CBasicString = path_to_target_file)
C3DMManager::GetModelPasswordProtected(this, int = 0, CBasicString = path_to_target_file, CBasicString = NULL);

C3DMManager::AddFile(int = 0; CBasicString = path_to_target_file, CBasicString = NULL, CBasicString = NULL, int 0);
```

`CBasicString` is the class used by the program to store strings. It has the following structure
(the definition is not complete as I only reverse engineered the fields I needed to write the harness).
```
typedef struct {
	void* vtablePtr;
	wchar_t* string;
	char filler[12];
	size_t string_len;
	size_t maybe_max_string_len;
	int null;
} CBasicString_t;
```

One issue I encountered was that the functions which take a `CBasicString` as argument try to free it after they're done with it.
The problem is that I manually allocate these structs with `malloc` and when the program tries to free them it detects memory corruption for some reason
(I guess mixing `malloc` with `delete` leads to some weird behaviour). 
My workaround was to patch the `free_CBasicString` in the DLL and replace its first opcode with 0xC3 (the opcode for `ret` in x86).
This causes the function to immediately return without trying to free anything. I can then free the memory myself in the harness.

![brava](/assets/img/brava/before_after.png)
_free_CBasicString before (left) and after (right) the patch_

Now we need to reimplement this logic in our harness.
Note that when declaring instances of a class defined in a DLL we need to allocate space for it and then manually import and call its constructor. 
[This article](https://www.codeproject.com/Articles/9405/Using-classes-exported-from-a-DLL-using-LoadLibrar) gives a great explaination of the process.
Here is an example (error handling omitted):

```c
// Load the DLL where the class is defined
HMODULE myr3dkernel = LoadLibraryA("myr3dkernel.dll");	
// Manually import the class constructor
C3DMManager_ctor = (C3DMManager_ctor_t)GetProcAddress(myr3dkernel, "??0C3DMManager@@QAE@XZ");
// Allocate size for the instance of the class
C3DMManager_t* C3DMManager = (C3DMManager_t*)malloc(sizeof(C3DMManager_t));
// Call the constructor. x86 C++ uses the thiscall calling convention where a pointer to the instance of the class is passed in ECX.
__asm { MOV ECX, C3DMManager};
C3DMManager_ctor();
```

The full harness can be found [here](https://github.com/Richard-AC).

## Fuzzing
---

Once the harness was ready I made sure it worked as expected by using the debug mode of DynamoRio.
```
C:\DynamoRIO\bin32\drrun.exe -c winafl.dll -debug -target_module opentext_harness.exe -target_method fuzzme -coverage_module myrdwgparser.dll -coverage_module myrdwgloader.dll -fuzz_iterations 10 -nargs 2 -- opentext_harness.exe E:\example.dwg
```

And I looked at the coverage using:
``` 
C:\DynamoRIO\bin32\drrun.exe -t drcov -- C:\winafl\build32\bin\Release\opentext_harness.exe E:\example.dwg
```
This command outputs a trace file which can be loaded into IDA Pro using the [Lighthouse](https://github.com/gaasedelen/lighthouse) plug-in 
to visualize coverage and make sure that our harness is exercising the parsing code correctly.

![brava](/assets/img/brava/coverage_lighthouse.png)
_Coverage of each function in myrdwgparser.dll when the harness is run with an example dwg file_

And finally I used a batch file to launch as many instances of winafl as I have cores on my machine.
```batch
@echo off
start cmd /k "afl-fuzz.exe -i in -o sync_dir -M fuzzer1 -f bla1.dwg -D C:\DynamoRIO\bin32 -t 50000 -- -coverage_module myrdwgparser.dll -fuzz_iterations 10000 -target_module opentext_harness.exe -target_method fuzzme -nargs 2 -- opentext_harness.exe @@"
start cmd /k "afl-fuzz.exe -i in -o sync_dir -S fuzzer2 -f bla2.dwg -D C:\DynamoRIO\bin32 -t 50000 -- -coverage_module myrdwgparser.dll -fuzz_iterations 10000 -target_module opentext_harness.exe -target_method fuzzme -nargs 2 -- opentext_harness.exe @@"
start cmd /k "afl-fuzz.exe -i in -o sync_dir -S fuzzer3 -f bla3.dwg -D C:\DynamoRIO\bin32 -t 50000 -- -coverage_module myrdwgparser.dll -fuzz_iterations 10000 -target_module opentext_harness.exe -target_method fuzzme -nargs 2 -- opentext_harness.exe @@"
start cmd /k "afl-fuzz.exe -i in -o sync_dir -S fuzzer4 -f bla4.dwg -D C:\DynamoRIO\bin32 -t 50000 -- -coverage_module myrdwgparser.dll -fuzz_iterations 10000 -target_module opentext_harness.exe -target_method fuzzme -nargs 2 -- opentext_harness.exe @@"
start cmd /k "afl-fuzz.exe -i in -o sync_dir -S fuzzer5 -f bla5.dwg -D C:\DynamoRIO\bin32 -t 50000 -- -coverage_module myrdwgparser.dll -fuzz_iterations 10000 -target_module opentext_harness.exe -target_method fuzzme -nargs 2 -- opentext_harness.exe @@"
start cmd /k "afl-fuzz.exe -i in -o sync_dir -S fuzzer6 -f bla6.dwg -D C:\DynamoRIO\bin32 -t 50000 -- -coverage_module myrdwgparser.dll -fuzz_iterations 10000 -target_module opentext_harness.exe -target_method fuzzme -nargs 2 -- opentext_harness.exe @@"
start cmd /k "afl-fuzz.exe -i in -o sync_dir -S fuzzer7 -f bla7.dwg -D C:\DynamoRIO\bin32 -t 50000 -- -coverage_module myrdwgparser.dll -fuzz_iterations 10000 -target_module opentext_harness.exe -target_method fuzzme -nargs 2 -- opentext_harness.exe @@"
start cmd /k "afl-fuzz.exe -i in -o sync_dir -S fuzzer8 -f bla8.dwg -D C:\DynamoRIO\bin32 -t 50000 -- -coverage_module myrdwgparser.dll -fuzz_iterations 10000 -target_module opentext_harness.exe -target_method fuzzme -nargs 2 -- opentext_harness.exe @@"
pause
```

## Crash triaging
---

After having accumulated thousands of crashes, manually reviewing every single one was no longer an option.
Furthermore, even though winafl is supposed to only record "unique" crashes, in my experience, it does save a lot of input files that trigger the same bug.

To assist in the crash triaging, I wrote a custom debugger whose goal is to run the crashing inputs and generate a hash that uniquely identifies a given bug. 
While not perfect in isolating unique bugs, it has helped cut down the amount of manual work significantly (turning ~1000 "unique" crashes reported by winafl into ~50 different hashes).
This is a generic tool that is not tied to this particular target so I won't detail it here but here is [a link to the github project](https://github.com/Richard-AC/TriageTool) for more information.

## Root cause analysis
---

Since the bugs I reported have not yet been patched, I won't disclose any detail here for now.
I will update this part with the detailed analysis once the bugs get patched.

## Reporting the bugs
---

![brava](/assets/img/brava/ZDI_tracking_number.png)

