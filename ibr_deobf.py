import re
import idaapi
import idc
import idautils
import ida_bytes
import ida_ua
import ida_kernwin
from collections import deque
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.core.asmblock import AsmCFG, AsmBlock
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import ExprInt, ExprId

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
        if isinstance(addr_expr, ExprInt):
            addr = int(addr_expr)
            size = expr.size // 8
            # Read directly from IDA active database
            if size == 8:
                val = idc.get_qword(addr)
            elif size == 4:
                val = idc.get_wide_dword(addr)
            elif size == 2:
                val = idc.get_wide_word(addr)
            elif size == 1:
                val = idc.get_wide_byte(addr)
            else:
                val = None
                
            if val is not None and val != idc.BADADDR:
                return ExprInt(val, expr.size)
        return super().mem_read(expr)

def find_jmp_reg_addr(jumps_addr, start_ea=None, end_ea=None):
    if start_ea is not None and end_ea is not None:
        start = start_ea
        end = end_ea
        print(f"[+] Scanning specified range: {start:#x} - {end:#x}")
    else:
        # Check if user selected a range in IDA UI
        selection, sel_start, sel_end = ida_kernwin.read_range_selection(None)
        if selection:
            start = sel_start
            end = sel_end
            print(f"[+] Scanning selected UI range: {start:#x} - {end:#x}")
        else:
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
                print("[-] No segment found to scan.")
                return

            start = idc.get_segm_start(target_seg)
            end = idc.get_segm_end(target_seg)
            print(f"[+] Scanning segment ({idc.get_segm_name(target_seg)}): {start:#x} - {end:#x}")

    # Iterate through all instructions (heads) in the target segment
    for ea in idautils.Heads(start, end):
        # Check if the head is classified as code
        if not idc.is_code(idc.get_full_flags(ea)):
            continue
        # Check if the instruction is a jmp
        if idc.print_insn_mnem(ea) != "jmp":
            continue
        if idc.get_operand_type(ea, 0) == idc.o_reg:
            reg = idc.print_operand(ea, 0)
            jumps_addr.append((ea, reg))

def find_next_jmp_reg(start_ea, max_depth=100):
    curr = start_ea
    visited = set()
    depth = 0
    while curr != idc.BADADDR and curr not in visited and depth < max_depth:
        visited.add(curr)
        depth += 1
        if not idc.is_code(idc.get_full_flags(curr)):
            size = idc.get_item_size(curr)
            if size <= 0:
                break
            curr += size
            continue
            
        mnem = idc.print_insn_mnem(curr).lower()
        if mnem == "jmp":
            op_type = idc.get_operand_type(curr, 0)
            if op_type == idc.o_reg:
                reg = idc.print_operand(curr, 0)
                return curr, reg
            elif op_type in (idc.o_near, idc.o_far):
                target = idc.get_operand_value(curr, 0)
                if target != idc.BADADDR:
                    curr = target
                    continue
                else:
                    break
            else:
                break
        elif mnem in ["ret", "retn"]:
            break
            
        size = idc.get_item_size(curr)
        if size <= 0:
            break
        curr += size
        
    return None, None

def backward_slice_path(path_history, entry_setup_eas=None):
    if not path_history:
        return []
        
    target_jmp = path_history[-1]
    reg = idc.print_operand(target_jmp, 0)
    start_family = get_reg_family(reg)
    if start_family is None:
        print(f"[-] Unknown register: {reg} at {target_jmp:#x}")
        return []
        
    tracked_regs = {start_family}
    all_slice_instrs = {}
    visited_eas = set()
    
    # Process jumps in reverse order of path_history
    for path_idx in range(len(path_history) - 1, -1, -1):
        if not tracked_regs:
            break
            
        start_addr = path_history[path_idx]
        current_addr = start_addr
        
        if start_addr == target_jmp:
            all_slice_instrs[start_addr] = (start_addr, idc.generate_disasm_line(start_addr, 0))
            visited_eas.add(start_addr)
            
        max_limit = 200
        count = 0
        
        while tracked_regs and count < max_limit and current_addr != idc.BADADDR:
            prev_addr = idc.prev_head(current_addr)
            
            is_boundary = False
            if prev_addr == idc.BADADDR:
                is_boundary = True
            else:
                mnem_prev = idc.print_insn_mnem(prev_addr).lower() if idc.is_code(idc.get_full_flags(prev_addr)) else ""
                if mnem_prev in ['call', 'ret', 'retn'] or mnem_prev.startswith('j'):
                    is_boundary = True
                    
            if is_boundary:
                refs = [r for r in idautils.CodeRefsTo(current_addr, 0) if r not in visited_eas]
                if refs:
                    current_addr = refs[0]
                    visited_eas.add(current_addr)
                    count += 1
                else:
                    break
            else:
                current_addr = prev_addr
                visited_eas.add(current_addr)
                count += 1
            
            if not idc.is_code(idc.get_full_flags(current_addr)):
                continue
                
            mnem = idc.print_insn_mnem(current_addr)
            if not mnem:
                continue
                
            mnem_lower = mnem.lower()
            
            if idc.get_operand_type(current_addr, 0) != idc.o_reg:
                continue
                
            if mnem_lower in ['cmp', 'test']:
                continue
                
            dest_op = idc.print_operand(current_addr, 0)
            dest_reg = get_reg_family(dest_op)
            
            if dest_reg in tracked_regs:
                all_slice_instrs[current_addr] = (current_addr, idc.generate_disasm_line(current_addr, 0))
                
                source_regs = set()
                for opnum in [1, 2]:
                    op_type = idc.get_operand_type(current_addr, opnum)
                    if op_type != -1:
                        op_str = idc.print_operand(current_addr, opnum)
                        source_regs.update(extract_registers(op_str))
                        
                is_overwrite = False
                if mnem_lower in ['mov', 'movabs', 'movzx', 'movsx', 'lea', 'pop']:
                    is_overwrite = True
                elif mnem_lower == 'xor' and idc.print_operand(current_addr, 0) == idc.print_operand(current_addr, 1):
                    is_overwrite = True
                    
                if is_overwrite:
                    tracked_regs.remove(dest_reg)
                    tracked_regs.update(source_regs)
                else:
                    tracked_regs.update(source_regs)

    # Fallback: if tracked_regs is still not empty, inspect entry_setup_eas if provided
    if tracked_regs and entry_setup_eas:
        for ea in reversed(sorted(entry_setup_eas)):
            if not tracked_regs:
                break
            if not idc.is_code(idc.get_full_flags(ea)):
                continue
            mnem = idc.print_insn_mnem(ea).lower()
            if idc.get_operand_type(ea, 0) != idc.o_reg:
                continue
            dest_op = idc.print_operand(ea, 0)
            dest_reg = get_reg_family(dest_op)
            if dest_reg in tracked_regs:
                all_slice_instrs[ea] = (ea, idc.generate_disasm_line(ea, 0))
                source_regs = set()
                for opnum in [1, 2]:
                    op_type = idc.get_operand_type(ea, opnum)
                    if op_type != -1:
                        op_str = idc.print_operand(ea, opnum)
                        source_regs.update(extract_registers(op_str))
                is_overwrite = False
                if mnem in ['mov', 'movabs', 'movzx', 'movsx', 'lea', 'pop']:
                    is_overwrite = True
                elif mnem == 'xor' and idc.print_operand(ea, 0) == idc.print_operand(ea, 1):
                    is_overwrite = True
                if is_overwrite:
                    tracked_regs.remove(dest_reg)
                    tracked_regs.update(source_regs)
                else:
                    tracked_regs.update(source_regs)
                    
    sorted_slice = sorted(all_slice_instrs.values(), key=lambda x: x[0])
    
    print(f"  --- Slice for {target_jmp:#x} (Path len: {len(path_history)}) ---")
    for ea, disasm in sorted_slice:
        print(f"    {ea:#x}: {disasm}")
    print("  ---------------------------------------------")
    
    return sorted_slice



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
    
    jmp_reg_full = family_to_reg(get_reg_family(jmp_reg), is_64bit)
    if jmp_reg_full:
        final_val = engine.eval_expr(ExprId(jmp_reg_full.upper(), reg_size))
    else:
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

def resolve_jump_slice(addr, reg, slice_instrs, global_regs, machine, lifter, mdis, container, loc_db, is_64bit):
    cond_idx = -1
    cond_type = None
    
    # Search for the LAST (closest to target jump) condition instruction in the slice
    for i in range(len(slice_instrs) - 1, -1, -1):
        ea, _ = slice_instrs[i]
        mnem = idc.print_insn_mnem(ea).lower()
        if mnem.startswith('set'):
            cond_idx = i
            cond_type = 'setcc'
            break
        elif mnem.startswith('cmov'):
            cond_idx = i
            cond_type = 'cmov'
            break
        elif mnem.startswith('lea'):
            op0 = idc.print_operand(ea, 0).lower()
            op1 = idc.print_operand(ea, 1).lower().replace(' ', '')
            if op0 in ['rcx', 'ecx'] and ('rcx*8' in op1 or 'ecx*8' in op1):
                cond_idx = i
                cond_type = 'lea'
                break
                
    dest_true, dest_false = None, None
    regs_true = {}
    
    if cond_type == 'lea':
        lea_addr, _ = slice_instrs[cond_idx]
        pre_eas = [ea for ea, _ in slice_instrs[:cond_idx]]
        pre_regs, engine = emulate_pre_cmov(
            pre_eas, global_regs, machine, lifter, mdis, container, loc_db, is_64bit
        )
        if pre_regs is not None:
            post_eas = [ea for ea, _ in slice_instrs[cond_idx : -1]]
            dest_true, regs_true = emulate_post_cmov(
                post_eas, 'rcx', 1, pre_regs,
                machine, lifter, mdis, container, loc_db, reg, is_64bit
            )
            dest_false, _ = emulate_post_cmov(
                post_eas, 'rcx', 0, pre_regs,
                machine, lifter, mdis, container, loc_db, reg, is_64bit
            )
            if dest_true is not None and dest_false is not None:
                print(f"  [+] Resolved destinations (lea) -> True: {dest_true:#x} | False: {dest_false:#x}")
                comment = f"True: {dest_true:#x}\nFalse: {dest_false:#x}"
                idc.set_cmt(addr, comment, 0)
                
                jmp_size = idc.get_item_size(addr)
                cond_name = "nz"
                slice_eas = {item[0] for item in slice_instrs}
                patch_indirect_jump_restore_non_slice(lea_addr, addr, jmp_size, slice_eas, dest_true, dest_false, cond_name)
    elif cond_type == 'setcc':
        setcc_addr, _ = slice_instrs[cond_idx]
        setcc_reg = idc.print_operand(setcc_addr, 0)
        setcc_reg_family = get_reg_family(setcc_reg)
        
        pre_eas = [ea for ea, _ in slice_instrs[:cond_idx]]
        pre_regs, engine = emulate_pre_cmov(
            pre_eas, global_regs, machine, lifter, mdis, container, loc_db, is_64bit
        )
        if pre_regs is not None:
            post_eas = [ea for ea, _ in slice_instrs[cond_idx + 1 : -1]]
            dest_true, regs_true = emulate_post_cmov(
                post_eas, setcc_reg_family, 1, pre_regs,
                machine, lifter, mdis, container, loc_db, reg, is_64bit
            )
            dest_false, _ = emulate_post_cmov(
                post_eas, setcc_reg_family, 0, pre_regs,
                machine, lifter, mdis, container, loc_db, reg, is_64bit
            )
            if dest_true is not None and dest_false is not None:
                print(f"  [+] Resolved destinations (setcc) -> True: {dest_true:#x} | False: {dest_false:#x}")
                comment = f"True: {dest_true:#x}\nFalse: {dest_false:#x}"
                idc.set_cmt(addr, comment, 0)
    elif cond_type == 'cmov':
        cmov_addr, _ = slice_instrs[cond_idx]
        dst_reg = idc.print_operand(cmov_addr, 0)
        src_reg = idc.print_operand(cmov_addr, 1)
        dst_family = get_reg_family(dst_reg)
        
        pre_eas = [ea for ea, _ in slice_instrs[:cond_idx]]
        pre_regs, engine = emulate_pre_cmov(
            pre_eas, global_regs, machine, lifter, mdis, container, loc_db, is_64bit
        )
        if pre_regs is not None and engine is not None:
            src_family = get_reg_family(src_reg)
            if dst_family:
                dst_reg_full = family_to_reg(dst_family, is_64bit)
                val_dst_expr = engine.eval_expr(ExprId(dst_reg_full, 64 if is_64bit else 32))
                val_dst = int(val_dst_expr) if isinstance(val_dst_expr, ExprInt) else 0
            else:
                val_dst = 0
            
            if src_family:
                src_reg_full = family_to_reg(src_family, is_64bit)
                val_src_expr = engine.eval_expr(ExprId(src_reg_full, 64 if is_64bit else 32))
                val_src = int(val_src_expr) if isinstance(val_src_expr, ExprInt) else 0
            else:
                instr = mdis.dis_instr(cmov_addr)
                val_src_expr = engine.eval_expr(instr.args[1])
                val_src = int(val_src_expr) if isinstance(val_src_expr, ExprInt) else 0
                
            post_eas = [ea for ea, _ in slice_instrs[cond_idx + 1 : -1]]
            dest_true, regs_true = emulate_post_cmov(
                post_eas, dst_family, val_src, pre_regs,
                machine, lifter, mdis, container, loc_db, reg, is_64bit
            )
            dest_false, _ = emulate_post_cmov(
                post_eas, dst_family, val_dst, pre_regs,
                machine, lifter, mdis, container, loc_db, reg, is_64bit
            )
            if dest_true is not None and dest_false is not None:
                print(f"  [+] Resolved destinations (cmov) -> True: {dest_true:#x} | False: {dest_false:#x}")
                comment = f"True: {dest_true:#x}\nFalse: {dest_false:#x}"
                idc.set_cmt(addr, comment, 0)
    else:
        print(f"  [-] No setcc/cmovcc/lea instruction found in slice for {addr:#x}.")

    return dest_true, dest_false, regs_true

def main(start_ea=None, end_ea=None):
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

    original_get_ir = lifter.get_ir
    def patched_get_ir(instr):
        try:
            return original_get_ir(instr)
        except NotImplementedError:
            return [], []
    lifter.get_ir = patched_get_ir

    initial_jumps = []
    find_jmp_reg_addr(initial_jumps, start_ea=start_ea, end_ea=end_ea)
    if not initial_jumps:
        print("[-] No initial JMP REG found.")
        return

    initial_jumps = sorted(initial_jumps, key=lambda x: x[0])
    first_jmp_ea, _ = initial_jumps[0]

    # Collect all setup instructions in the entry basic block preceding first_jmp_ea
    entry_setup_eas = []
    curr = first_jmp_ea
    count = 0
    while curr != idc.BADADDR and count < 40:
        prev = idc.prev_head(curr)
        if prev == idc.BADADDR:
            break
        mnem = idc.print_insn_mnem(prev).lower()
        if mnem in ['call', 'ret', 'retn'] or mnem.startswith('j'):
            break
        entry_setup_eas.append(prev)
        curr = prev
        count += 1

    if is_64bit:
        global_regs = {'RSP': 0x200000}
    else:
        global_regs = {'ESP': 0x200000}

    worklist = deque()
    worklist.append((first_jmp_ea, [first_jmp_ea]))

    resolved_jumps = {}
    visited_path_keys = set()

    print("\n=== RESOLVING AND COMMENTING INDIRECT JUMPS (WORKLIST TRAVERSAL) ===")

    while True:
        while worklist:
            current_jmp_ea, path_history = worklist.popleft()

            path_key = (current_jmp_ea, tuple(path_history))
            if path_key in visited_path_keys:
                continue
            visited_path_keys.add(path_key)

            reg = idc.print_operand(current_jmp_ea, 0)
            print(f"\n[+] Processing JMP REG at {current_jmp_ea:#x} (JMP {reg}) | Path depth: {len(path_history)}")

            slice_instrs = backward_slice_path(path_history, entry_setup_eas=entry_setup_eas)
            if not slice_instrs:
                print(f"  [-] Empty slice for {current_jmp_ea:#x}")
                continue

            dest_true, dest_false, regs_true = resolve_jump_slice(
                current_jmp_ea, reg, slice_instrs, global_regs, machine, lifter, mdis, container, loc_db, is_64bit
            )

            if dest_true is not None and dest_false is not None:
                resolved_jumps[current_jmp_ea] = (dest_true, dest_false)
                if regs_true:
                    global_regs.update(regs_true)

                for dest, branch_name in [(dest_true, "True"), (dest_false, "False")]:
                    next_jmp_ea, next_reg = find_next_jmp_reg(dest)
                    if next_jmp_ea is not None:
                        if next_jmp_ea in resolved_jumps:
                            print(f"  [->] Branch {branch_name} ({dest:#x}) leads to ALREADY RESOLVED JMP REG at {next_jmp_ea:#x}")
                        elif next_jmp_ea in path_history:
                            print(f"  [->] Branch {branch_name} ({dest:#x}) loops back to JMP REG in current path at {next_jmp_ea:#x}")
                        else:
                            new_path = path_history + [next_jmp_ea]
                            path_key = (next_jmp_ea, tuple(new_path))
                            if path_key not in visited_path_keys:
                                print(f"  [->] Branch {branch_name} ({dest:#x}) leads to next JMP REG at {next_jmp_ea:#x}")
                                worklist.append((next_jmp_ea, new_path))
                    else:
                        print(f"  [->] Branch {branch_name} ({dest:#x}) ended without next JMP REG.")
            else:
                print(f"  [-] Could not resolve destinations for {current_jmp_ea:#x}")

        unvisited_remaining = [ea for ea, _ in initial_jumps if ea not in resolved_jumps and (ea, (ea,)) not in visited_path_keys]
        if unvisited_remaining:
            next_unvisited = unvisited_remaining[0]
            worklist.append((next_unvisited, [next_unvisited]))
        else:
            break

if __name__ == "__main__":
    # main()
    main(0x10025D00, 0x10026BF3)
