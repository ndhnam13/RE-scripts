# Indirect jump, indirect branch

Compile một chương trình bằng ollvm với pass indirect branch 

`clang.exe test.c -o ibr.exe -O2 -mllvm -ibr`

## Phân tích pattern của file ví dụ (setcc)

<img width="740" height="428" alt="image-20260716103135464" src="https://github.com/user-attachments/assets/6415e9bc-3fd1-492e-a082-249701a0dde3" />

<img width="872" height="424" alt="image-20260716103205562" src="https://github.com/user-attachments/assets/9fd5485c-66b9-494a-9207-1df33ec94918" />

<img width="618" height="201" alt="image-20260716104043148" src="https://github.com/user-attachments/assets/4042aced-15ab-4307-ab90-1f8846d9a2c1" />

Do chương trình không biết được giá trị chính xác của thanh ghi rax cho nên trong pseudocode bị cắt ngắn, không biết được toàn bộ luồng hoạt động của chương trình

Thấy rằng đối với mẫu này địa chỉ chính xác được tính toán như sau:

- Lấy địa chỉ base của một jumptable `off_140028000`
- cmp + setcc REG, lúc này REG sẽ có thể có 2 giá trị 1 hoặc 0. Lệnh setcc sẽ được sử dụng để lấy offset một giá trị của jumptable
- mov REG, [base + REG + ...], để lấy một giá trị từ jumptable
- add REG, imm + jmp REG, cộng với 1 giá trị rồi nhảy đến địa chỉ đích

Vậy thì các lệnh nhảy với lệnh setcc đằng trước sẽ luôn có 2 địa chỉ

```assembly
.text:0000000140001033                 mov     edi, 2
.text:0000000140001038                 xor     eax, eax
.text:000000014000103A                 cmp     edi, [rsp+58h+var_2C]
.text:000000014000103E                 setl    al
.text:0000000140001041                 lea     rbx, off_140028000
.text:0000000140001048                 mov     r14, 0BD2F849908B8CEF6h
.text:0000000140001052                 mov     rax, [rbx+rax*8]
.text:0000000140001056                 add     rax, r14
.text:0000000140001059                 mov     esi, 2
.text:000000014000105E                 jmp     rax
```

Có 2 giá trị 0x140028000 và 0x140028008 là:

```
.data:0000000140028000 off_140028000   dq 42D07B683747416Ah    ; DATA XREF: main+41↑o
.data:0000000140028008                 dq 42D07B683747418Eh
```

Trong trường hợp al = 0 => RAX = 0x140001060, al = 1 => RAX = 0x140001084

## Ý tưởng deobf

Để khôi phục lại địa chỉ cho các lệnh JMP có thể làm như sau

### Bước 1: Tìm tất cả lệnh JMP REG

Duyệt toàn bộ segment `.text` để tìm tất cả các lệnh `jmp reg`

### Bước 2: Backward Slicing

Với mỗi lệnh `jmp reg` tìm được, thêm thanh ghi được dùng làm địa chỉ đích vào `tracked_regs` rồi trace ngược lên các lệnh trước đó.

Với mỗi lệnh, kiểm tra xem nó có ghi hoặc làm thay đổi một thanh ghi/stack slot đang nằm trong tập theo dõi hay không:

- Nếu lệnh ghi vào thanh ghi đang tracked:
  - Đánh dấu lệnh đó thuộc slice
  - Nếu lệnh ghi đè hoàn toàn giá trị (`mov`, `movabs`, `movzx`, `movsx`, `lea`, `pop`, hoặc `xor reg, reg`): loại thanh ghi đích khỏi `tracked_regs` và thêm các thanh ghi nguồn vào
  - Nếu lệnh vẫn phụ thuộc vào giá trị cũ (`add`, `sub`, `and`, ...): giữ thanh ghi đích trong `tracked_regs` và thêm thêm các thanh ghi nguồn
  
- Nếu lệnh ghi vào stack slot đang tracked (ví dụ `mov [rsp+18h], rcx`):
  - Đánh dấu lệnh đó thuộc slice
  - Nếu là `mov`: loại stack slot đích khỏi `tracked_stack`, thêm thanh ghi/stack slot nguồn vào tập theo dõi
  - Cơ chế này kết nối các lệnh load từ stack (ví dụ `mov rax, [rsp+18h]`) với lệnh store tương ứng

- Nếu lệnh không tác động: bỏ qua

Ngoài thanh ghi, script còn theo dõi các stack slot (ví dụ `[rsp+18h]`) qua `tracked_stack`. Khi backward slice gặp lệnh đọc từ stack (ví dụ `mov rax, [rsp+18h]` với `rax` đang tracked), nó sẽ thêm stack slot `0x18` vào `tracked_stack` rồi tiếp tục trace ngược để tìm lệnh store vào slot đó.

#### Điều kiện dừng trace

- `tracked_regs` và `tracked_stack` đều rỗng
- Gặp lệnh `call`, `ret`, `retn`
- Gặp lệnh `jmp`
- Đã trace quá giới hạn

#### Ví dụ backward slicing

```assembly
.text:0000000140001000                 push    r14
.text:0000000140001002                 push    rsi
.text:0000000140001003                 push    rdi
.text:0000000140001004                 push    rbp
.text:0000000140001005                 push    rbx
.text:0000000140001006                 sub     rsp, 30h
.text:000000014000100A                 lea     rcx, Enter_number__ ; "Enter number: "
.text:0000000140001011                 call    sub_140001120
.text:0000000140001016                 lea     rcx, _d         ; "%d"
.text:000000014000101D                 lea     rdx, [rsp+58h+var_2C]
.text:0000000140001022                 call    sub_140001180
.text:0000000140001027                 lea     rcx, Buffer     ; "Prime numbers are:"
.text:000000014000102E                 call    puts
.text:0000000140001033                 mov     edi, 2
.text:0000000140001038                 xor     eax, eax
.text:000000014000103A                 cmp     edi, [rsp+58h+var_2C]
.text:000000014000103E                 setl    al
.text:0000000140001041                 lea     rbx, qword_140028000
.text:0000000140001048                 mov     r14, 13632260389884972790
.text:0000000140001052                 mov     rax, [rbx+rax*8]
.text:0000000140001056                 add     rax, r14
.text:0000000140001059                 mov     esi, 2
.text:000000014000105E                 jmp     rax             ; True: 0x140001084
.text:000000014000105E                                         ; False: 0x140001060
```

- Đối với đoạn này bắt đầu với `tracked_regs = {rax}` 

- `mov esi, 2` không tác động, không đánh dấu lệnh này => `tracked_regs = {rax}`  
- `add rax, r14` => `tracked_reg = {rax, r14}`
- `mov rax, [rbx+rax*8]` => `tracked_reg = {r14, rbx, rax}`
- `mov r14, imm` => `tracked_reg = {rbx, rax}`
- `lea rbx, offset` => `tracked_reg = {rax}`
- `setl al` => `tracked_reg{rax}`
- `cmp edi, [rsp+58h+var_2C]` không đánh dấu => `tracked_reg{rax}`
- `xor eax, eax` => Lúc này `tracked_regs` rỗng, ta có slice sau

```assembly
0x140001038: xor     eax, eax
0x14000103e: setl    al
0x140001041: lea     rbx, qword_140028000
0x140001048: mov     r14, 13632260389884972790
0x140001052: mov     rax, [rbx+rax*8]
0x140001056: add     rax, r14
0x14000105e: jmp     rax
```

### Bước 3: Nhận diện pattern (setcc, cmovcc)

Sau khi có slice, script quét từ đầu slice để xác định pattern:

1. SETCC (`setl`, `sete`, `setne`...): Lệnh set condition code, thanh ghi đích luôn có 2 giá trị 0 hoặc 1
2. CMOVCC (`cmovl`, `cmove`...): Lệnh conditional move, thanh ghi đích có thể giữ nguyên hoặc bị ghi đè bằng giá trị nguồn

### Bước 4: Symbolic Execution

Để tìm ra 2 địa chỉ đích của lệnh `jmp reg`, sử dụng miasm để symbolic execute slice vừa thu được.

Quá trình symbolic execution được chia thành 2 lần cho cả 3 pattern:

Pre-emulation:
- Emulate các lệnh trong slice trước lệnh setcc/cmov
- Input: các giá trị thanh ghi từ `global_regs` (trạng thái propagate từ các block trước)
- Output: trạng thái thanh ghi sau khi emulate + engine instance (để eval operand CMOV)

Post-emulation:
- Emulate các lệnh trong slice sau lệnh setcc/cmov (không bao gồm lệnh `jmp reg`)
- Override thanh ghi đích với giá trị cụ thể (0 hoặc 1 cho setcc, `val_dst` hoặc `val_src` cho cmov)
- Input: trạng thái thanh ghi từ + giá trị override
- Output: giá trị concrete của thanh ghi đích JMP (= địa chỉ đích) + trạng thái thanh ghi cập nhật

Mỗi pattern chạy pha 2 **hai lần** để thu được 2 địa chỉ đích:

| Pattern | Trường hợp True | Trường hợp False |
|---------|-----------------|-------------------|
| SETCC   | `setcc_reg = 1` | `setcc_reg = 0` |
| CMOVCC  | `dst = val_src` (điều kiện đúng, move xảy ra) | `dst = val_dst` (điều kiện sai, giữ nguyên) |

- Có một số hàm trong chương trình sẽ đưa base jumptable hoặc 1 giá trị vào 1 thanh ghi sau đó tái sử dụng lại cho các lệnh sau 

<img width="807" height="506" alt="image-20260716171652783" src="https://github.com/user-attachments/assets/2054227c-631c-4398-8622-a2d8a88cca2c" />

Địa chỉ của Jumptable được đưa vào rbx và một giá trị được đưa vào r14, sau khi lệnh `0x14000105E jmp rax` được thực thi đến `loc_140001070` sẽ sử dụng lại rbx và r14 trước đó

Nhưng khi symbolic execute sẽ chỉ chạy đúng đoạn slice mà ta tìm được, vậy khi symbolic execute `loc_140001070` thì sẽ không thể resolve được 2 địa chỉ đích do không biết giá trị thật của rbx và r14

Để giải quyết, sort các địa chỉ `jmp reg` tăng dần và thực hiện symbolic execute từng slice một. Sau mỗi lần emulate, bất kỳ thanh ghi nào đạt được giá trị cụ thể (`ExprInt`) sẽ được lưu vào `global_regs` và truyền qua các block tiếp theo

## Patching

Khi có được 2 địa chỉ đích, tiến hành patch trong IDA database

Script tự tạo bytecode cho lệnh jump:
- JCC: 6 bytes = opcode 2 bytes (`0F 8x`) + relative offset 4 bytes
- JMP: S5 bytes = opcode 1 byte (`E9`) + relative offset 4 bytes
- Offset được tính: `target - (current_addr + instruction_length)`

1. Thu thập lệnh: Lặp qua tất cả lệnh trong range `[setcc_addr, jmp_addr + jmp_size)` 
2. Tách lệnh không thuộc slice: Với mỗi lệnh, nếu không thuộc `slice_eas` → lưu lại bytecode gốc. Ví dụ `mov esi, 2` trong ví dụ trên không thuộc slice, bytecode của nó sẽ được giữ lại
3. Tạo patch data: Nối theo thứ tự:
   - Bytecode các lệnh không thuộc slice (đặt lên đầu)
   - `Jcc dest_true` (6 bytes): conditional jump đến nhánh True
   - `JMP dest_false` (5 bytes): unconditional jump đến nhánh False
4. Padding NOP: Nếu patch nhỏ hơn vùng gốc -> thêm `0x90` (NOP) để lấp đầy
5. Patch trong IDB

### Kết quả

<img width="562" height="204" alt="image-20260716194300638" src="https://github.com/user-attachments/assets/cde4ea93-c504-4d92-84fd-a00d80d2be4a" />

<img width="630" height="520" alt="image-20260716194322513" src="https://github.com/user-attachments/assets/30a61b84-98d4-411e-9fbf-433fae594141" />

<img width="913" height="439" alt="image-20260716194346116" src="https://github.com/user-attachments/assets/76216cd5-638c-4610-acd2-59f87913525d" />

## Phân tích pattern của sample EarthLamia (setcc, cmovcc)

Dùng script deobf file test cho sample EarthLamia chỉ có một số jmp reg resolve được 

Số còn lại chưa resolve được là do lệnh CMOVCC. Lệnh CMOV được sử dụng để lấy offset của 1 giá trị trong jumptable

<img width="930" height="407" alt="image-20260717103528894" src="https://github.com/user-attachments/assets/1b183bdd-ff30-40fc-bc28-83941f3a7a20" />

### Xử lý CMOVCC

Hướng trace ngược vẫn sử dụng đúng ý tưởng backward slicing như cho SETCC.

Đối với CMOV thì cần symbex 2 lần. Chia slice ra làm 2 phần: trước CMOV và từ CMOV trở đi:

1. Pre-CMOV: Symbolic execute các lệnh trước CMOV để biết được trạng thái thanh ghi. Sau đó sử dụng `engine.eval_expr()` trên operand miasm của lệnh CMOV để lấy giá trị của cả `dst` và `src`:
   
   - Giá trị hiện tại của thanh ghi đích

   - Giá trị nguồn (sẽ được gán nếu điều kiện đúng)
   
2. Post-CMOV: Symbolic execute từ sau CMOV với 2 trường hợp:
   - Điều kiện đúng: `dst = val_src` (move xảy ra) -> tính địa chỉ nhánh True
   - Điều kiện sai: `dst = val_dst` (giữ nguyên) -> tính địa chỉ nhánh False

## Phân tích pattern mẫu PlugX

### Pattern 1

Hướng giải quyết:

- Tìm jmp reg đầu hàm sau đó backward slice và symbex resolve được 2 T/F

- Đi đến nhánh T, lưu lại nhánh F

- Lưu lại cả địa chỉ của các nhánh đã được resolve

- Tìm `JMP REG` trong nhánh T, backward slice đến hết nhánh T, nếu `tracked_regs` vẫn còn, tiếp tục backward slice từ địa chỉ của của `JMP REG` nhánh trước đó tiếp tục đến khi không `tracked_regs` rỗng, symbex slice để resolve T/F, lại đi đến nhánh T và lưu lại nhánh F

- Đối với các nhánh đã resolve bỏ qua khi gặp lại

- Tiếp tục làm như vậy cho đến khi resolve hết tất cả các nhánh

Ví dụ:

Đây là `JMP REG` đầu tiên của hàm

```assembly
.text:10025DF3 loc_10025DF3:                           ; CODE XREF: fn_decrypt_config+D2↑j
.text:10025DF3                 lea     ecx, [esp+64h+var_46]
.text:10025DF7                 mov     eax, [ecx-0Ah]
.text:10025DFA                 mov     byte ptr [eax+6], 0
.text:10025DFE                 mov     edx, [ecx-0Ah]
.text:10025E01                 call    sub_10026D8C
.text:10025E06                 lea     ecx, [esp+0Ch+arg_24]
.text:10025E0A                 push    4
.text:10025E0C                 push    ecx
.text:10025E0D                 push    offset byte_100480AC
.text:10025E12                 call    eax
.text:10025E14                 add     esp, 0Ch
.text:10025E17                 test    eax, eax
.text:10025E19                 setz    byte ptr [esp+3]
.text:10025E1E                 mov     eax, 1976796641
.text:10025E23                 mov     ebx, 1395262558
.text:10025E28                 mov     edx, dword_10040870
.text:10025E2E                 lea     ecx, [edx-1738205772]
.text:10025E34                 lea     edi, [edx-1738205768]
.text:10025E3A                 add     edx, 2556761844
.text:10025E40                 cmp     eax, 164689989
.text:10025E45                 cmovge  edx, edi
.text:10025E48                 mov     edx, [edx]
.text:10025E4A                 add     edx, ebx
.text:10025E4C                 jmp     edx             ; True: 0x10026465
.text:10025E4C                                         ; False: 0x10025e4e
```

Sau khi resolve đi tới nhánh True tại 0x10026465, quét từ đây xuống gặp `JMP EDX`

```assembly
.text:10026459                 add     ecx, 986515B4h
.text:1002645F                 mov     edx, [edx]
.text:10026461                 add     edx, ebx
.text:10026463                 jmp     edx
.text:10026465 loc_10026465:                           ; CODE XREF: fn_decrypt_config+14C↑j
.text:10026465                 lea     edx, [ecx+13Ch]
.text:1002646B                 lea     edi, [ecx+8Ch]
.text:10026471                 cmp     eax, 1244202890
.text:10026476                 cmovl   edx, edi
.text:10026479                 mov     edx, [edx]
.text:1002647B                 add     edx, ebx
.text:1002647D                 jmp     edx
```

Khi backward slice từ 0x1002647D thì chưa tìm được giá trị của ECX, nên sẽ tiếp tục backward slice từ `JMP REG` trước đó là 0x10025E4C

### Pattern 2

```assembly
.text:10025EAC                 mov     eax, 2B083668h
.text:10025EB1                 cmp     ebp, [esp+64h+var_34]
.text:10025EB5                 jb      short loc_10025EBC
.text:10025EB7                 mov     eax, 95275CA9h
.text:10025EBC
.text:10025EBC loc_10025EBC:                           ; CODE XREF: fn_decrypt_config+1B5↑j
.text:10025EBC                 mov     ecx, dword_10040870
.text:10025EC2                 cmp     eax, 9D0F845h
.text:10025EC7                 jl      loc_10026441
.text:10025ECD                 lea     edx, [ecx-679AEA48h]
.text:10025ED3                 jmp     loc_10026447
```

```assembly
.text:10026441 loc_10026441:                           ; CODE XREF: fn_decrypt_config+1C7↑j
.text:10026441                 lea     edx, [ecx-679AE90Ch]
.text:10026447
.text:10026447 loc_10026447:                           ; CODE XREF: fn_decrypt_config+1D3↑j
.text:10026447                 add     ecx, 986515B4h
.text:1002644D                 mov     edx, [edx]
.text:1002644F                 add     edx, ebx
.text:10026451                 jmp     edx
```

Pattern này không sử dụng các conditional instruction như `CMOVCC` hay `SETCC` mà setup các tham số cho JMP trước sau đó CMP (Khả năng của obf CFF) rồi có 2 lệnh JMP, 2 lệnh JMP đó đều đi đến `JMP REG` (Mỗi lệnh JMP sẽ là một điều kiện) 
