import re
import idaapi
import idc
import idautils
import ida_bytes
import ida_ua
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.core.asmblock import AsmCFG, AsmBlock
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import ExprInt, ExprId, ExprMem

# Inclusive address range used by main(). Pass different values to main() or
# find_jmp_reg_addr() when analysing another dispatcher.
DEFAULT_SCAN_START_EA = 0x10026BF4
DEFAULT_SCAN_END_EA = 0x10026D41

cond_jump_insts = {
    'jo': b'\x0f\x80', 'jno': b'\x0f\x81', 
    'js': b'\x0f\x88', 'jns': b'\x0f\x89', 
    'je': b'\x0f\x84', 'jz': b'\x0f\x84', 
    'jne': b'\x0f\x85', 'jnz': b'\x0f\x85', 
    'jb': b'\x0f\x82', 'jnae': b'\x0f\x82', 
    'jae': b'\x0f\x83', 'jnb': b'\x0f\x83', 
    'jbe': b'\x0f\x86', 'jna': b'\x0f\x86', 
    'ja': b'\x0f\x87', 'jnbe': b'\x0f\x87', 
    'jl': b'\x0f\x8c', 'jnge': b'\x0f\x8c', 
    'jge': b'\x0f\x8d', 'jnl': b'\x0f\x8d', 
    'jle': b'\x0f\x8e', 'jng': b'\x0f\x8e', 
    'jg': b'\x0f\x8f', 'jnle': b'\x0f\x8f', 
    'jp': b'\x0f\x8a', 'jpe': b'\x0f\x8a', 
    'jnp': b'\x0f\x8b', 'jpo': b'\x0f\x8b'
}

def assemble_jump(target, current_addr, cond=None):
    if cond is not None:
        jcc_name = 'j' + cond
        opcode = cond_jump_insts.get(jcc_name)
        if opcode is None:
            raise ValueError(f"Unknown condition: {cond}")
        inst_len = 6
        offset = target - (current_addr + inst_len)
        return opcode + offset.to_bytes(4, 'little', signed=True)
    else:
        opcode = b"\xE9"
        inst_len = 5
        offset = target - (current_addr + inst_len)
        return opcode + offset.to_bytes(4, 'little', signed=True)

def patch_indirect_jump_restore_non_slice(setcc_addr, jmp_addr, jmp_size, slice_eas, dest_true, dest_false, cond):
    patch_size = (jmp_addr + jmp_size) - setcc_addr
    
    # 1. Collect all instructions in the range [setcc_addr, jmp_addr + jmp_size)
    range_instrs = []
    curr = setcc_addr
    while curr < jmp_addr + jmp_size:
        size = idc.get_item_size(curr)
        if size <= 0:
            print(f"  [-] Error: invalid instruction size {size} at {curr:#x}")
            return False
        range_instrs.append((curr, size))
        curr += size
        
    # 2. Extract and concatenate bytes of all non-slice instructions
    non_slice_bytes = b""
    non_slice_size = 0
    for ea, size in range_instrs:
        if ea not in slice_eas:
            bytes_data = idc.get_bytes(ea, size)
            if bytes_data:
                non_slice_bytes += bytes_data
                non_slice_size += size
                print(f"  [+] Saving non-slice instruction at {ea:#x} (size {size}): {idc.generate_disasm_line(ea, 0)}")
                
    # 3. Assemble patch: Non-slice instructions + Jcc (6 bytes) + Jmp (5 bytes)
    jcc_addr = setcc_addr + non_slice_size
    jmp_addr_part = jcc_addr + 6
    
    patch_data = non_slice_bytes
    patch_data += assemble_jump(dest_true, jcc_addr, cond=cond)
    patch_data += assemble_jump(dest_false, jmp_addr_part)
    
    if len(patch_data) < patch_size:
        patch_data += b"\x90" * (patch_size - len(patch_data))
    elif len(patch_data) > patch_size:
        print(f"  [-] Error: patch data ({len(patch_data)}) exceeds patch size ({patch_size})")
        return False
        
    # 4. Apply patch to IDA database
    ida_bytes.del_items(setcc_addr, ida_bytes.DELIT_SIMPLE, patch_size)
    ida_bytes.patch_bytes(setcc_addr, patch_data)
    
    # 5. Re-create instructions in the patched range
    curr_patch = setcc_addr
    while curr_patch < setcc_addr + patch_size:
        ida_ua.create_insn(curr_patch)
        new_size = idc.get_item_size(curr_patch)
        if new_size <= 0:
            new_size = 1
        curr_patch += new_size
        
    return True

REG_FAMILIES = {
    'rax': {'rax', 'eax', 'ax', 'al', 'ah'},
    'rbx': {'rbx', 'ebx', 'bx', 'bl', 'bh'},
    'rcx': {'rcx', 'ecx', 'cx', 'cl', 'ch'},
    'rdx': {'rdx', 'edx', 'dx', 'dl', 'dh'},
    'rsi': {'rsi', 'esi', 'si', 'sil'},
    'rdi': {'rdi', 'edi', 'di', 'dil'},
    'rsp': {'rsp', 'esp', 'sp', 'spl'},
    'rbp': {'rbp', 'ebp', 'bp', 'bpl'},
    'r8':  {'r8', 'r8d', 'r8w', 'r8b'},
    'r9':  {'r9', 'r9d', 'r9w', 'r9b'},
    'r10': {'r10', 'r10d', 'r10w', 'r10b'},
    'r11': {'r11', 'r11d', 'r11w', 'r11b'},
    'r12': {'r12', 'r12d', 'r12w', 'r12b'},
    'r13': {'r13', 'r13d', 'r13w', 'r13b'},
    'r14': {'r14', 'r14d', 'r14w', 'r14b'},
    'r15': {'r15', 'r15d', 'r15w', 'r15b'}
}

ALL_REG_MEMBERS = {}
for fam, members in REG_FAMILIES.items():
    for m in members:
        ALL_REG_MEMBERS[m] = fam

def get_reg_family(reg_name):
    if not reg_name:
        return None
    return ALL_REG_MEMBERS.get(reg_name.lower(), None)

def family_to_reg(family_name, is_64bit):
    if not family_name:
        return None
    if is_64bit:
        return family_name.upper()
    else:
        mapping = {
            'rax': 'EAX', 'rbx': 'EBX', 'rcx': 'ECX', 'rdx': 'EDX',
            'rsi': 'ESI', 'rdi': 'EDI', 'rsp': 'ESP', 'rbp': 'EBP'
        }
        return mapping.get(family_name.lower())

def extract_registers(op_str):
    if not op_str:
        return set()
    tokens = re.findall(r'[a-zA-Z0-9]+', op_str)
    found_regs = set()
    for token in tokens:
        family = get_reg_family(token)
        if family:
            found_regs.add(family)
    return found_regs

class IDASymbolicExecutionEngine(SymbolicExecutionEngine):
    def __init__(self, lifter, container, state=None):
        super().__init__(lifter, state)
        self.container = container

    def mem_read(self, expr):
        addr_expr = self.eval_expr(expr.ptr)
        mem_expr = ExprMem(addr_expr, expr.size)

        # Prefer values written by the symbolic engine (notably the synthetic
        # stack at 0x200000) over bytes from the IDA database.
        stored_value = super().mem_read(mem_expr)
        if stored_value != mem_expr:
            return stored_value

        if isinstance(addr_expr, ExprInt):
            addr = int(addr_expr)
            size = expr.size // 8

            # IDA may return FF bytes for an unmapped address, so get_bytes()
            # alone is not a valid mapped-memory test.
            if all(ida_bytes.is_loaded(addr + offset) for offset in range(size)):
                data = ida_bytes.get_bytes(addr, size)
                if data is not None and len(data) == size:
                    return ExprInt(int.from_bytes(data, "little"), expr.size)

        return stored_value

def find_jmp_reg_addr(jumps_addr, start_ea=None, end_ea=None):
    """Append JMP-register instructions in an optional inclusive EA range."""
    # Find the .text segment or default to the first segment
    text_seg = None
    first_seg = None
    for seg in idautils.Segments():
        if first_seg is None:
            first_seg = seg
        name = idc.get_segm_name(seg)
        if name == ".text":
            text_seg = seg
            break

    target_seg = text_seg if text_seg is not None else first_seg
    if target_seg is None:
        return

    seg_start = idc.get_segm_start(target_seg)
    seg_end = idc.get_segm_end(target_seg)

    start = seg_start if start_ea is None else max(start_ea, seg_start)
    end_inclusive = (seg_end - 1) if end_ea is None else min(end_ea, seg_end - 1)
    if start > end_inclusive:
        raise ValueError(
            f"Invalid scan range {start_ea!r}..{end_ea!r} for segment "
            f"{seg_start:#x}..{seg_end:#x}"
        )

    # idautils.Heads() uses an exclusive end; the public end_ea is inclusive.
    for ea in idautils.Heads(start, end_inclusive + 1):
        # Check if the head is classified as code
        if not idc.is_code(idc.get_full_flags(ea)):
            continue
        # Check if the instruction is a jmp
        if idc.print_insn_mnem(ea) != "jmp":
            continue
        if idc.get_operand_type(ea, 0) == idc.o_reg:
            reg = idc.print_operand(ea, 0)
            jumps_addr.append((ea, reg))

    return jumps_addr

def get_stack_slot(ea, opnum):
    """Return a normalized ESP/RSP-relative slot, or None for other operands."""
    op_type = idc.get_operand_type(ea, opnum)
    if op_type not in (idc.o_phrase, idc.o_displ):
        return None

    operand = idc.print_operand(ea, opnum).lower()
    families = extract_registers(operand)
    if "rsp" not in families or families - {"rsp"}:
        return None

    if op_type == idc.o_phrase:
        return 0

    import ida_ida
    bits = 64 if ida_ida.inf_is_64bit() else 32
    value = idc.get_operand_value(ea, opnum) & ((1 << bits) - 1)
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value


def backward_slice(addr, reg=None, lower_bound=None, cross_jumps=False):
    if reg is None:
        reg = idc.print_operand(addr, 0)
        
    start_family = get_reg_family(reg)
    if start_family is None:
        print(f"[-] Unknown register: {reg}")
        return []
        
    tracked_regs = {start_family}
    tracked_stack = set()
    slice_instructions = [(addr, idc.generate_disasm_line(addr, 0))]
    
    current_addr = addr
    max_limit = 150
    count = 0
    
    while (tracked_regs or tracked_stack) and count < max_limit:
        # Move to previous instruction
        prev_addr = idc.prev_head(current_addr)
        if prev_addr == idc.BADADDR:
            break
            
        current_addr = prev_addr
        count += 1

        if lower_bound is not None and current_addr < lower_bound:
            break
        
        # Check if it is code
        if not idc.is_code(idc.get_full_flags(current_addr)):
            continue
            
        mnem = idc.print_insn_mnem(current_addr)
        if not mnem:
            continue
            
        mnem_lower = mnem.lower()
        
        # Cross layout-adjacent dispatcher stubs only when the caller supplied
        # an explicit lower bound. Calls and returns remain hard boundaries.
        if mnem_lower in ['call', 'ret', 'retn']:
            break

        if mnem_lower.startswith('j'):
            if cross_jumps and lower_bound is not None:
                continue
            break
            
        # Track stores to stack slots used by a later handler. This connects
        # loads such as [esp+18h] with their producer in the dispatcher block.
        dest_stack = get_stack_slot(current_addr, 0)
        if dest_stack is not None and dest_stack in tracked_stack:
            if mnem_lower in ['cmp', 'test']:
                continue

            slice_instructions.append(
                (current_addr, idc.generate_disasm_line(current_addr, 0))
            )

            source_regs = set()
            source_stack = set()
            for opnum in [1, 2]:
                op_type = idc.get_operand_type(current_addr, opnum)
                if op_type == idc.o_void:
                    continue
                stack_slot = get_stack_slot(current_addr, opnum)
                if stack_slot is not None:
                    source_stack.add(stack_slot)
                else:
                    source_regs.update(
                        extract_registers(idc.print_operand(current_addr, opnum))
                    )

            if mnem_lower in ['mov', 'movabs']:
                tracked_stack.remove(dest_stack)
            tracked_regs.update(source_regs)
            tracked_stack.update(source_stack)
            continue

        # We only check if the instruction writes to a register
        if idc.get_operand_type(current_addr, 0) != idc.o_reg:
            continue
            
        # Ignore non-modifying instructions
        if mnem_lower in ['cmp', 'test']:
            continue
            
        dest_op = idc.print_operand(current_addr, 0)
        dest_reg = get_reg_family(dest_op)
        
        if dest_reg in tracked_regs:
            # Instruction is relevant
            slice_instructions.append((current_addr, idc.generate_disasm_line(current_addr, 0)))
            
            # Extract source registers from op 1 and op 2
            source_regs = set()
            source_stack = set()
            for opnum in [1, 2]:
                op_type = idc.get_operand_type(current_addr, opnum)
                if op_type == idc.o_void:
                    continue
                stack_slot = get_stack_slot(current_addr, opnum)
                if stack_slot is not None and mnem_lower != 'lea':
                    source_stack.add(stack_slot)
                else:
                    op_str = idc.print_operand(current_addr, opnum)
                    source_regs.update(extract_registers(op_str))
                    
            # Check if it is a complete overwrite
            is_overwrite = False
            if mnem_lower in ['mov', 'movabs', 'movzx', 'movsx', 'lea', 'pop']:
                is_overwrite = True
            elif mnem_lower == 'xor' and idc.print_operand(current_addr, 0) == idc.print_operand(current_addr, 1):
                is_overwrite = True
                # xor r, r produces a constant zero; the old code accidentally
                # re-added r as its own dependency.
                source_regs.clear()
                source_stack.clear()
                
            if is_overwrite:
                tracked_regs.remove(dest_reg)
                tracked_regs.update(source_regs)
                tracked_stack.update(source_stack)
            else:
                tracked_regs.update(source_regs)
                tracked_stack.update(source_stack)
                
    # Sort by address for printing
    slice_instructions = sorted(slice_instructions, key=lambda x: x[0])
    
    print("  --- Slice ---")
    for ea, disasm in slice_instructions:
        print(f"    {ea:#x}: {disasm}")
    print("  -------------")
    
    return slice_instructions



def emulate_pre_cmov(pre_eas, global_regs, machine, lifter, mdis, container, loc_db, is_64bit):
    reg_size = 64 if is_64bit else 32
    if not pre_eas:
        return {k.upper(): v for k, v in global_regs.items()}, IDASymbolicExecutionEngine(lifter, container, {ExprId(k.upper(), reg_size): ExprInt(v, reg_size) for k, v in global_regs.items()})
        
    asmcfg = AsmCFG(loc_db)
    block = AsmBlock(loc_db, loc_db.gen_loc_key())
    for ea in pre_eas:
        instr = mdis.dis_instr(ea)
        block.lines.append(instr)
    asmcfg.add_block(block)
    
    ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
    
    init_state = {}
    for reg_name, val in global_regs.items():
        init_state[ExprId(reg_name.upper(), reg_size)] = ExprInt(val, reg_size)
        
    engine = IDASymbolicExecutionEngine(lifter, container, init_state)
    if list(ircfg.blocks.values()):
        engine.eval_updt_irblock(list(ircfg.blocks.values())[0])
    
    if is_64bit:
        GP_REGS = ['RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RSP', 'RBP', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15']
    else:
        GP_REGS = ['EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'ESP', 'EBP']
        
    updated_regs = {}
    for reg_name in GP_REGS:
        reg_id = ExprId(reg_name, reg_size)
        val = engine.symbols.read(reg_id)
        if isinstance(val, ExprInt):
            updated_regs[reg_name] = int(val)
            
    return updated_regs, engine

def emulate_post_cmov(post_eas, dst_reg_family, override_val, pre_regs, machine, lifter, mdis, container, loc_db, jmp_reg, is_64bit):
    reg_size = 64 if is_64bit else 32
    if not post_eas:
        return override_val, pre_regs
        
    asmcfg = AsmCFG(loc_db)
    block = AsmBlock(loc_db, loc_db.gen_loc_key())
    for ea in post_eas:
        instr = mdis.dis_instr(ea)
        block.lines.append(instr)
    asmcfg.add_block(block)
    
    ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
    
    init_state = {}
    for reg_name, val in pre_regs.items():
        init_state[ExprId(reg_name.upper(), reg_size)] = ExprInt(val, reg_size)
        
    dst_reg = family_to_reg(dst_reg_family, is_64bit)
    if dst_reg:
        init_state[ExprId(dst_reg.upper(), reg_size)] = ExprInt(override_val, reg_size)
    
    engine = IDASymbolicExecutionEngine(lifter, container, init_state)
    if list(ircfg.blocks.values()):
        engine.eval_updt_irblock(list(ircfg.blocks.values())[0])
    
    final_val = engine.eval_expr(ExprId(jmp_reg.upper(), reg_size))
    
    if is_64bit:
        GP_REGS = ['RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RSP', 'RBP', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15']
    else:
        GP_REGS = ['EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'ESP', 'EBP']
        
    updated_regs = {}
    for reg_name in GP_REGS:
        reg_id = ExprId(reg_name, reg_size)
        val = engine.symbols.read(reg_id)
        if isinstance(val, ExprInt):
            updated_regs[reg_name] = int(val)
            
    if isinstance(final_val, ExprInt):
        return int(final_val), updated_regs
    return None, updated_regs

def main(scan_start=DEFAULT_SCAN_START_EA, scan_end=DEFAULT_SCAN_END_EA):
    # Initialize Miasm elements using the binary file currently open in IDA
    loc_db = LocationDB()
    filepath = idc.get_input_file_path()
    with open(filepath, "rb") as f:
        container = Container.from_stream(f, loc_db)
        
    import ida_ida
    is_64bit = ida_ida.inf_is_64bit()
    if is_64bit:
        machine = Machine("x86_64")
    else:
        machine = Machine("x86_32")
    mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)
    lifter = machine.lifter_model_call(loc_db)

    # Patch get_ir to handle unimplemented instructions gracefully
    original_get_ir = lifter.get_ir
    def patched_get_ir(instr):
        try:
            return original_get_ir(instr)
        except NotImplementedError:
            return [], []
    lifter.get_ir = patched_get_ir

    # Find JMP REG addresses
    jumps_addr = []
    find_jmp_reg_addr(jumps_addr, scan_start, scan_end)
    range_label = "entire .text" if scan_start is None else f"{scan_start:#x}..{scan_end:#x}"
    print(f"[*] Scanned {range_label}: found {len(jumps_addr)} JMP-register instructions")
    
    # Sort jumps sequentially to ensure proper register propagation
    jumps_addr = sorted(jumps_addr, key=lambda x: x[0])
    
    # Global register state to propagate across jumps
    if is_64bit:
        global_regs = {
            'RSP': 0x200000
        }
    else:
        global_regs = {
            'ESP': 0x200000
        }
    
    print("\n=== RESOLVING AND COMMENTING INDIRECT JUMPS ===")
    for addr, reg in jumps_addr:
        # print(f"Analyzing {addr:#x}, JMP {reg}")
        
        # Get backward slice
        slice_instrs = backward_slice(
            addr,
            reg,
            lower_bound=scan_start,
            cross_jumps=scan_start is not None,
        )
        
        # Find if slice has a setcc, cmovcc, or lea pattern
        setcc_idx = -1
        cmov_idx = -1
        lea_idx = -1
        for i, (ea, _) in enumerate(slice_instrs):
            mnem = idc.print_insn_mnem(ea).lower()
            if mnem.startswith('set'):
                setcc_idx = i
                break
            elif mnem.startswith('cmov'):
                cmov_idx = i
                break
            elif mnem.startswith('lea'):
                op0 = idc.print_operand(ea, 0).lower()
                op1 = idc.print_operand(ea, 1).lower().replace(' ', '')
                if op0 in ['rcx', 'ecx'] and ('rcx*8' in op1 or 'ecx*8' in op1):
                    lea_idx = i
                    break
                    
        if lea_idx != -1:
            lea_addr, _ = slice_instrs[lea_idx]
            
            # 1. Pre-lea emulation: instructions before lea_addr
            pre_eas = [ea for ea, _ in slice_instrs[:lea_idx]]
            pre_regs, engine = emulate_pre_cmov(
                pre_eas, global_regs, machine, lifter, mdis, container, loc_db, is_64bit
            )
            
            if pre_regs is not None:
                # Post-lea instructions after lea_addr (excluding JMP instruction itself)
                post_eas = [ea for ea, _ in slice_instrs[lea_idx : -1]]
                
                # Emulate Case True: RCX = 1
                dest_true, regs_true = emulate_post_cmov(
                    post_eas, 'rcx', 1, pre_regs,
                    machine, lifter, mdis, container, loc_db, reg, is_64bit
                )
                
                # Emulate Case False: RCX = 0
                dest_false, regs_false = emulate_post_cmov(
                    post_eas, 'rcx', 0, pre_regs,
                    machine, lifter, mdis, container, loc_db, reg, is_64bit
                )
                
                if dest_true is not None and dest_false is not None:
                    print(f"  [+] Resolved destinations (lea) -> True: {dest_true:#x} | False: {dest_false:#x}")
                    
                    comment = f"True: {dest_true:#x}\nFalse: {dest_false:#x}"
                    idc.set_cmt(addr, comment, 0)
                    # print(f"  [+] Added comment to {addr:#x}")
                    
                    # Patch in IDA database
                    # jmp_size = idc.get_item_size(addr)
                    # cond_name = "nz"
                    # slice_eas = {item[0] for item in slice_instrs}
                    # success = patch_indirect_jump_restore_non_slice(lea_addr, addr, jmp_size, slice_eas, dest_true, dest_false, cond_name)
                    # if success:
                    #     print(f"  [+] Patched jump block at {lea_addr:#x} successfully.")
                    
                    # Propagate registers (e.g. from the True branch)
                    global_regs.update(regs_true)
                else:
                    print(f"  [-] Failed to resolve lea destinations dynamically.")
            else:
                print(f"  [-] Failed pre-lea emulation.")
                
        elif setcc_idx != -1:
            setcc_addr, _ = slice_instrs[setcc_idx]
            setcc_reg = idc.print_operand(setcc_addr, 0)
            setcc_reg_family = get_reg_family(setcc_reg)
            
            # 1. Pre-setcc emulation: instructions before setcc_addr
            pre_eas = [ea for ea, _ in slice_instrs[:setcc_idx]]
            pre_regs, engine = emulate_pre_cmov(
                pre_eas, global_regs, machine, lifter, mdis, container, loc_db, is_64bit
            )
            
            if pre_regs is not None:
                # Post-setcc instructions after setcc_addr (excluding JMP instruction itself)
                post_eas = [ea for ea, _ in slice_instrs[setcc_idx + 1 : -1]]
                
                # Emulate Case True: setcc_reg = 1
                dest_true, regs_true = emulate_post_cmov(
                    post_eas, setcc_reg_family, 1, pre_regs,
                    machine, lifter, mdis, container, loc_db, reg, is_64bit
                )
                
                # Emulate Case False: setcc_reg = 0
                dest_false, regs_false = emulate_post_cmov(
                    post_eas, setcc_reg_family, 0, pre_regs,
                    machine, lifter, mdis, container, loc_db, reg, is_64bit
                )
                
                if dest_true is not None and dest_false is not None:
                    print(f"  [+] Resolved destinations -> True: {dest_true:#x} | False: {dest_false:#x}")
                    
                    # Comment the resolved destinations at the JMP instruction
                    comment = f"True: {dest_true:#x}\nFalse: {dest_false:#x}"
                    idc.set_cmt(addr, comment, 0)
                    # print(f"  [+] Added comment to {addr:#x}")
                    
                    # Patch in IDA database
                    # jmp_size = idc.get_item_size(addr)
                    # cond_name = idc.print_insn_mnem(setcc_addr).lower()[3:]
                    # slice_eas = {item[0] for item in slice_instrs}
                    # success = patch_indirect_jump_restore_non_slice(setcc_addr, addr, jmp_size, slice_eas, dest_true, dest_false, cond_name)
                    # if success:
                    #     print(f"  [+] Patched jump block at {setcc_addr:#x} successfully.")
                    
                    # Propagate registers (e.g. from the True branch)
                    global_regs.update(regs_true)
                else:
                    print(f"  [-] Failed to resolve destinations dynamically.")
            else:
                print(f"  [-] Failed pre-setcc emulation.")
        elif cmov_idx != -1:
            cmov_addr, _ = slice_instrs[cmov_idx]
            dst_reg = idc.print_operand(cmov_addr, 0)
            src_reg = idc.print_operand(cmov_addr, 1)
            
            dst_family = get_reg_family(dst_reg)
            
            # 1. Pre-cmov emulation: remaining instructions before cmov_addr
            pre_eas = [ea for ea, _ in slice_instrs[:cmov_idx]]
            pre_regs, engine = emulate_pre_cmov(
                pre_eas, global_regs, machine, lifter, mdis, container, loc_db, is_64bit
            )
            
            if pre_regs is not None and engine is not None:
                # Disassemble the CMOV instruction using Miasm to get its operands
                instr = mdis.dis_instr(cmov_addr)
                
                # Evaluate destination operand in the pre-cmov state
                val_dst_expr = engine.eval_expr(instr.args[0])
                val_dst = int(val_dst_expr) if isinstance(val_dst_expr, ExprInt) else 0
                
                # Evaluate source operand in the pre-cmov state
                val_src_expr = engine.eval_expr(instr.args[1])
                val_src = int(val_src_expr) if isinstance(val_src_expr, ExprInt) else 0
                
                # Post-cmov instructions after cmov_addr (excluding JMP instruction itself)
                post_eas = [ea for ea, _ in slice_instrs[cmov_idx + 1 : -1]]
                
                # Emulate Case True: dst = val_src
                dest_true, regs_true = emulate_post_cmov(
                    post_eas, dst_family, val_src, pre_regs,
                    machine, lifter, mdis, container, loc_db, reg, is_64bit
                )
                
                # Emulate Case False: dst = val_dst
                dest_false, regs_false = emulate_post_cmov(
                    post_eas, dst_family, val_dst, pre_regs,
                    machine, lifter, mdis, container, loc_db, reg, is_64bit
                )
                
                if dest_true is not None and dest_false is not None:
                    print(f"  [+] Resolved destinations (cmov) -> True: {dest_true:#x} | False: {dest_false:#x}")
                    
                    comment = f"True: {dest_true:#x}\nFalse: {dest_false:#x}"
                    idc.set_cmt(addr, comment, 0)
                    # print(f"  [+] Added comment to {addr:#x}")
                    
                    # Patch in IDA database
                    # jmp_size = idc.get_item_size(addr)
                    # cond_name = idc.print_insn_mnem(cmov_addr).lower()[4:]
                    # slice_eas = {item[0] for item in slice_instrs}
                    # success = patch_indirect_jump_restore_non_slice(cmov_addr, addr, jmp_size, slice_eas, dest_true, dest_false, cond_name)
                    # if success:
                    #     print(f"  [+] Patched jump block at {cmov_addr:#x} successfully.")
                        
                    global_regs.update(regs_true)
                else:
                    print(f"  [-] Failed to resolve cmov destinations dynamically.")
            else:
                print(f"  [-] Failed pre-cmov emulation.")
        else:
            print(f"  [-] No setcc/cmovcc/lea instruction found in slice.")

if __name__ == "__main__":
    main()
    # main(None, None)
