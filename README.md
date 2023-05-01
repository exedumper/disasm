# disasm
A simple x86/x64 disassembler based on Zydis

### Intro

This disassembler comes with EXE parser. Based on Zydis (https://github.com/zyantific/zydis), it supports x86 and x64 instruction and extension.

Currently in beta testing phase, bug reports are welcomed!

### Usage

`disasm file.exe | more`

`disasm file.exe > file.txt`

### Example Output

x64 disassembly:

```
00401000  sub rsp, 0x28                                                                                   
00401004  mov r9d, 0x00                                                                                   
0040100A  lea r8, [0x0040100A00000FF6]                                                                    
00401011  lea rdx, [0x0040101100001006]                                                                   
00401018  mov rcx, 0x00                                                                                   
0040101F  call [0x0040101F0000202D]                                                                       
00401025  mov ecx, eax                                                                                    
00401027  call [0x0040102700002015]                                                                       
0040102D  add [rax], al                                                                                   
0040102F  add [rax], al                                                                                   
00401031  add [rax], al                              
```

### Limitation

Support 640KB EXE (code section) only although this can be adjusted easily in the source file.

No hex bytes of CPU instruction are printed.

### License

The Zydis.dll is licensed as MIT, but this `disasm.asm` is CC0 (loyalty-free).

