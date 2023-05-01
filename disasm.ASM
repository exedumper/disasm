; disasm.asm (CC0)
; Based on Zydis
;
; Developed by Boo Khan Ming (2023)
;
format PE console
entry start

include 'win32a.inc'

struct ZydisDecodedInstruction ; (sizeof=0x148, align=0x8, copyof_249)
       machine_mode    dd ?
       mnemonic        dd ?
       length          db ?
       a               db ?
       b               db ?
       c               db ?
       encoding        dd ?
       opcode_map      dd ?
       opcode          db ?
       stack_width     db ?
       operand_width   db ?
       address_width   db ?
       operand_count   db ?
       operand_count_visible db ?
                             db ?
                             db ?
                             db ?
                             db ?
                             db ?
                             db ?
       attributes      dq ?
       cpu_flags       dq ?
       fpu_flags       dq ?
       avx             rb 0x24   ;ZydisDecodedInstructionAvx_ ?
       meta            rb 0x14   ;ZydisDecodedInstructionMeta_ ?
       raw             rb 0xD8   ;ZydisDecodedInstructionRaw_ ?
ends

struct ZydisDisassembledInstruction ; (sizeof=0x4D0, align=0x8, copyof_251)
       runtime_address dq ?
       info            ZydisDecodedInstruction
       operands        rb 0x320 - 8
       text            rb 0x60 + 8
ends

BUFFER_SIZE = 640 * 1024

section '.data' readable writable

_message0 db 'Usage: disasm <executable filename>',13,10
_msglen0  = $ - _message0
_message1 db 'Error opening file.',13,10
_msglen1  = $ - _message1
_message2 db 'Error reading file.',13,10
_msglen2  = $ - _message2
_message3 db 'Invalid EXE',13,10
_msglen3  = $ - _message3
_message4 db 'Invalid PE',13,10
_msglen4  = $ - _message4
_message5 db 'Only 32-bit (x86) PE is supported.',13,10
_msglen5  = $ - _message5
_message6 db 'Only 64-bit (x64) PE is supported.',13,10
_msglen6  = $ - _message6
_message7 db 'Code section not found.',13,10
_msglen7  = $ - _message7
_message8 db 'ZydisDisassembleIntel failed.',13,10
_msglen8  = $ - _message8
_dummy    dd ?
_short    db ?
          db 0
_double   dw ?
_hexnum   rb 8
_hexval   rb 2
_digits   db '0123456789ABCDEF'
_space1   db 32,32
_len1     = $ - _space1
_space2   db 32
_len2     = $ - _space2
_filename rb MAX_PATH
_fnlen    dd ?
_buffer   rb BUFFER_SIZE
_len      dd ?
_ptr      dd ?
_handle   dd ?
_stdout   dd ?
_count    dd ?
_offset   dd 0
_pe_start dd ?
_pe_id_r  rb 4
_pe_id    db 'P','E',0,0
_mz_id_r  rb 2
_mz_id    db 'M','Z'
_machine  dw ?
_section  dw ?
_baseofcode dd ?
_fileptr  dd ?
_magic    dw ?
_virtualaddress   dd ?
_sizeofrawdata    dd ?
_pointertorawdata dd ?
_sectiontable     rb 40
_zydismode        dd 0
_runtimeaddress   dd ?
_instruction   ZydisDisassembledInstruction

align 8

IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_AMD64 = 0x8664
PE32 = 0x10b
PE64 = 0x20b

OffsetToBaseOfCode = 0xac - 0x80
OffsetToImageBaseForPE32 = 0xb4 - 0x80
OffsetToImageBaseForPE64 = 0xb0 - 0x80
OffsetToSectionTableForPE32 = 0x178 - 0x80
OffsetToSectionTableForPE64 = 0x178 - 0x80 + 16
OffsetToMagicNumber = 0x98 - 0x80

section '.code' code readable executable

start:
        invoke  GetCommandLine
        push    eax
        mov     edi, eax
        or      ecx, -1
        xor     eax, eax
        repnz   scasb           ; Calculate total length of command line arguments
        not     ecx
        pop     eax
        mov     dword [_fnlen], ecx
        push    eax
        mov     edi, eax
        or      ecx, -1
        mov     eax, 32
        repnz   scasb           ; Calculate length of first command line argument (APPNAME)
        not     ecx
        pop     eax
        inc     ecx
        sub     dword [_fnlen], ecx     ; Compute the length of second command line argument (_FILENAME)
        cmp     dword [_fnlen], 0
        jle     .err0
        add     eax, ecx
        mov     ecx, dword [_fnlen]
        mov     esi, eax
        lea     edx, [_filename]
        mov     edi, edx
        rep     movsb
        ;invoke  GetStdHandle, -11
        ;invoke  WriteConsole, eax, _filename, dword [_fnlen], _dummy, 0
        invoke  CreateFile, _filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
        mov     dword [_handle], eax
        cmp     eax, INVALID_HANDLE_VALUE
        je      .err1
        invoke  GetStdHandle, -11
        mov     dword [_stdout],eax

        invoke  ReadFile, dword [_handle], _mz_id_r, 2, _len, 0
        test    eax, eax
        jz      .err2
        movzx   ebx, word [_mz_id_r]
        cmp     bx, word [_mz_id]
        jnz     .err3
        invoke  SetFilePointer, dword [_handle], 0x3C, 0, FILE_BEGIN
        invoke  ReadFile, dword [_handle], _pe_start, 4, _len, 0
        test    eax, eax
        jz      .err2
        invoke  SetFilePointer, dword [_handle], dword [_pe_start], 0, FILE_BEGIN
        invoke  ReadFile, dword [_handle], _pe_id_r, 4, _len, 0
        test    eax, eax
        jz      .err2
        mov     ebx, dword [_pe_id_r]
        cmp     ebx, dword [_pe_id]
        jnz     .err4
        invoke  ReadFile, dword [_handle], _machine, 2, _len, 0
        test    eax, eax
        jz      .err2
        movzx   ebx, word [_machine]
        cmp     ebx, IMAGE_FILE_MACHINE_AMD64
        jz     .is64
        mov     [_zydismode],1
.is64:
        invoke  ReadFile, dword [_handle], _section, 2, _len, 0
        test    eax, eax
        jz      .err2

        mov     ebx, dword [_pe_start]
        add     ebx, OffsetToMagicNumber
        mov     [_fileptr], ebx
        invoke  SetFilePointer, dword [_handle], dword [_fileptr] , 0, FILE_BEGIN
        invoke  ReadFile, dword [_handle], _magic, 2, _len, 0
        test    eax, eax
        jz      .err2

        mov     ebx, dword [_pe_start]
        add     ebx, OffsetToBaseOfCode
        mov     [_fileptr], ebx
        invoke  SetFilePointer, dword [_handle], dword [_fileptr] , 0, FILE_BEGIN
        invoke  ReadFile, dword [_handle], _baseofcode, 4, _len, 0
        test    eax, eax
        jz      .err2

        movzx   ebx, word [_magic]
        cmp     ebx, PE32
        jz      .isPE32

        mov     ebx, dword [_pe_start]
        add     ebx, OffsetToImageBaseForPE64
        mov     [_fileptr], ebx
        invoke  SetFilePointer, dword [_handle], dword [_fileptr] , 0, FILE_BEGIN
        invoke  ReadFile, dword [_handle], _runtimeaddress, 4, _len, 0
        test    eax, eax
        jz      .err2
        mov     ebx, [_baseofcode]
        add     [_runtimeaddress], ebx

        mov     ebx, dword [_pe_start]
        add     ebx, OffsetToSectionTableForPE64
        mov     [_fileptr], ebx
        invoke  SetFilePointer, dword [_handle], dword [_fileptr] , 0, FILE_BEGIN
        jmp     .continue
.isPE32:
        mov     ebx, dword [_pe_start]
        add     ebx, OffsetToImageBaseForPE32
        mov     [_fileptr], ebx
        invoke  SetFilePointer, dword [_handle], dword [_fileptr] , 0, FILE_BEGIN
        invoke  ReadFile, dword [_handle], _runtimeaddress, 4, _len, 0
        test    eax, eax
        jz      .err2
        mov     ebx, [_baseofcode]
        add     [_runtimeaddress], ebx

        mov     ebx, dword [_pe_start]
        add     ebx, OffsetToSectionTableForPE32
        mov     [_fileptr], ebx
        invoke  SetFilePointer, dword [_handle], dword [_fileptr] , 0, FILE_BEGIN

.continue:
        movzx   ecx, word [_section]
.scan:     ;loop through all section table until match found for code section
        push    ecx
        invoke  ReadFile, dword [_handle], _sectiontable, 40, _len, 0
        test    eax, eax
        jz      .err2
        pop     ecx
        mov     ebx, dword [_sectiontable + 12]
        mov     [_virtualaddress], ebx
        mov     ebx, dword [_sectiontable + 16]
        mov     [_sizeofrawdata], ebx
        mov     ebx, dword [_sectiontable + 20]
        mov     [_pointertorawdata], ebx
        mov     ebx, dword [_baseofcode]
        cmp     ebx, dword [_virtualaddress]
        jz      .donescan
        dec     ecx
        jnz     .scan
        jmp     .err7
.donescan:
        invoke  SetFilePointer, dword [_handle], dword [_pointertorawdata] , 0, FILE_BEGIN
        invoke  ReadFile, dword [_handle], _buffer, [_sizeofrawdata], _len, 0
        test    eax, eax
        jz      .err2
        ;mov     ecx, dword [_len]
        ;test    ecx, ecx
        ;jz      .close
        invoke  CloseHandle, [_handle]

.decode:
        lea     edx, [_buffer]
        add     edx, [_offset]

        cinvoke  ZydisDisassembleIntel, [_zydismode], 0,[_runtimeaddress], edx, [_len], _instruction
        test    eax,eax
        js      .err8
        push    eax
        mov     edx, [_runtimeaddress]
        mov     ecx, 8
        call    ConvertLongHex
        call    PrintOffset
        call    PrintLongSpace
        mov     edx, 96
        lea     esi, [_instruction.text]
        call    Print
        call    PrintLine
        movzx   edx, byte [_instruction.info.length]
        add     [_runtimeaddress], edx
        add     [_offset], edx
        mov     edx, [_offset]
        cmp     edx, [_sizeofrawdata]
        jae     .done
        pop     eax
        test    eax,eax
        jns     .decode
        jmp     .done


;    while (ZYAN_SUCCESS(ZydisDisassembleIntel(
;        /* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
;        /* runtime_address: */ runtime_address,
;        /* buffer:          */ data + offset,
;        /* length:          */ sizeof(data) - offset,
;        /* instruction:     */ &instruction
;    ))) {
;        printf("%016" PRIX64 "  %s\n", runtime_address, instruction.text);
;        offset += instruction.info.length;
;        runtime_address += instruction.info.length;
;    }

.close:
        invoke  CloseHandle, [_handle]
        jmp     .done

.err0:
        lea     edx, [_message0]
        mov     ecx, _msglen0
        jmp     .error

.err1:
        lea     edx, [_message1]
        mov     ecx, _msglen1
        jmp     .error

.err2:
        lea     edx, [_message2]
        mov     ecx, _msglen2
        jmp     .error

.err3:
        lea     edx, [_message3]
        mov     ecx, _msglen3
        jmp     .error

.err4:
        lea     edx, [_message4]
        mov     ecx, _msglen4
        jmp     .error

.err5:
        lea     edx, [_message5]
        mov     ecx, _msglen5
        jmp     .error

.err6:
        lea     edx, [_message6]
        mov     ecx, _msglen6
        jmp     .error

.err7:
        lea     edx, [_message7]
        mov     ecx, _msglen7
        jmp     .error

.err8:
        lea     edx, [_message8]
        mov     ecx, _msglen8

.error:
        invoke  GetStdHandle, -11
        invoke  WriteConsole, eax, edx, ecx, _dummy, 0

.done:
        invoke  ExitProcess,0

PrintLongSpace:
        mov     edx, _len1
        lea     esi, [_space1]
        call    Print
        ret
PrintShortSpace:
        mov     edx, _len2
        lea     esi, [_space2]
        call    Print
        ret
PrintLine:
        mov     edx, 2
        mov     [_double], 0x0A0D
        lea     esi, [_double]
        call    Print
        ret
PrintOffset:
        mov     edx, 8
        lea     esi, [_hexnum]
        call    Print
        ret
PrintHex:
        mov     edx, 2
        lea     esi, [_hexval]
        call    Print
        ret
PrintChar:      
        mov     edx, 1
        lea     esi, [_short]
        call    Print
        ret
Print:
        ;invoke  WriteConsole, dword [_stdout], esi, edx, _dummy, 0
        invoke  WriteFile, dword [_stdout], esi, edx, _dummy, 0
        ret

ConvertLongHex:    ;-) Nice code snippet by Tomasz Grysztar (flat assembler)
        xor      ebx,ebx
.loop1:
        rol      edx,4
        mov      eax,edx
        and      eax,1111b
        mov      al,[_digits+eax]
        mov      [ebx+_hexnum],al
        inc      ebx
        dec      ecx
        jnz      .loop1
        ret
            
section '.idata' import readable writable

 library kernel32, 'KERNEL32.DLL',\
         Zydis, 'Zydis.dll'

 import kernel32,\
        GetStdHandle, 'GetStdHandle', \
        WriteConsole, 'WriteConsoleA', \
        CreateFile, 'CreateFileA', \
        ReadFile, 'ReadFile', \
        WriteFile, 'WriteFile', \
        CloseHandle, 'CloseHandle', \
        GetCommandLine, 'GetCommandLineA', \
        SetFilePointer, 'SetFilePointer', \
        ExitProcess,'ExitProcess'

  import Zydis,\
        ZydisDisassembleIntel, "ZydisDisassembleIntel"
