# Indirect jump, indirect branch

Compile một chương trình bằng ollvm với pass indirect branch 

`clang.exe test.c -o ibr.exe -O2 -mllvm -ibr`

## Phân tích pattern của file ví dụ (setcc)

![image-20260716103135464](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20260716103135464.png)

![image-20260716103205562](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20260716103205562.png)

![image-20260716104043148](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20260716104043148.png)

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

![image-20260716171652783](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20260716171652783.png)

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

![image-20260716194300638](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20260716194300638.png)

![image-20260716194322513](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20260716194322513.png)

![image-20260716194346116](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20260716194346116.png)

## Phân tích pattern của sample EarthLamia (setcc, cmovcc)

Dùng script deobf file test cho sample EarthLamia chỉ có một số jmp reg resolve được 

Số còn lại chưa resolve được là do lệnh CMOVCC. Lệnh CMOV được sử dụng để lấy offset của 1 giá trị trong jumptable

![image-20260717103528894](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20260717103528894.png)

### Xử lý CMOVCC

Hướng trace ngược vẫn sử dụng đúng ý tưởng backward slicing như cho SETCC.

Đối với CMOV thì cần symbex 2 lần. Chia slice ra làm 2 phần: trước CMOV và từ CMOV trở đi:

1. Pre-CMOV: Symbolic execute các lệnh trước CMOV để biết được trạng thái thanh ghi. Sau đó sử dụng `engine.eval_expr()` trên operand miasm của lệnh CMOV để lấy giá trị của cả `dst` và `src`:
   
   - Giá trị hiện tại của thanh ghi đích

   - Giá trị nguồn (sẽ được gán nếu điều kiện đúng)
   
2. Post-CMOV: Symbolic execute từ sau CMOV với 2 trường hợp:
   - Điều kiện đúng: `dst = val_src` (move xảy ra) -> tính địa chỉ nhánh True
   - Điều kiện sai: `dst = val_dst` (giữ nguyên) -> tính địa chỉ nhánh False
