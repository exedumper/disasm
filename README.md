# disasm
A simple x86/x64 disassembler based on Zydis

### Intro

This disassembler comes with EXE parser. Based on Zydis (https://github.com/zyantific/zydis), it supports x86 and x64 instruction and extension.

### Usage

`disasm file.exe | more`

`disasm file.exe > file.txt`

### Example Output

x64 disassembly:

```
00001000  sub rsp, 0x28                                                                                   
00001004  mov r9d, 0x00                                                                                   
0000100A  lea r8, [0x0000100A00000FF6]                                                                    
00001011  lea rdx, [0x0000101100001006]                                                                   
00001018  mov rcx, 0x00                                                                                   
0000101F  call [0x0000101F0000202D]                                                                       
00001025  mov ecx, eax                                                                                    
00001027  call [0x0000102700002015]                                                                       
0000102D  add [rax], al                                                                                   
0000102F  add [rax], al                                                                                   
00001031  add [rax], al                      
```

### Limitation

Support 640KB EXE (code section) only although this can be adjusted easily in the source file.

No hex bytes of CPU instruction are printed.

### License

The Zydis.dll is licensed as MIT, but this `disasm.asm` is CC0 (loyalty-free).

