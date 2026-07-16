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

def patch_indirect_jump(setcc_addr, patch_size, dest_true, dest_false, cond):
    patch_data = assemble_jump(dest_true, setcc_addr, cond=cond)
    patch_data += assemble_jump(dest_false, setcc_addr + 6)
    
    if len(patch_data) < patch_size:
        patch_data += b"\x90" * (patch_size - len(patch_data))
    elif len(patch_data) > patch_size:
        print(f"  [-] Error: patch data ({len(patch_data)}) exceeds patch size ({patch_size})")
        return False
        
    ida_bytes.del_items(setcc_addr, ida_bytes.DELIT_SIMPLE, patch_size)
    ida_bytes.patch_bytes(setcc_addr, patch_data)
    
    ida_ua.create_insn(setcc_addr)
    ida_ua.create_insn(setcc_addr + 6)
    
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

def find_jmp_reg_addr(jumps_addr):
    # Iterate through all instructions (heads) in the database
    for ea in idautils.Heads():
        # Check if the head is classified as code
        if not idc.is_code(idc.get_full_flags(ea)):
            continue
        # Check if the instruction is a jmp
        if idc.print_insn_mnem(ea) != "jmp":
            continue
        if idc.get_operand_type(ea, 0) == idc.o_reg:
            reg = idc.print_operand(ea, 0)
            jumps_addr.append((ea, reg))

def backward_slice(addr, reg=None):
    if reg is None:
        reg = idc.print_operand(addr, 0)
        
    start_family = get_reg_family(reg)
    if start_family is None:
        print(f"[-] Unknown register: {reg}")
        return []
        
    tracked_regs = {start_family}
    slice_instructions = [(addr, idc.generate_disasm_line(addr, 0))]
    
    current_addr = addr
    max_limit = 150
    count = 0
    
    while tracked_regs and count < max_limit:
        # Move to previous instruction
        prev_addr = idc.prev_head(current_addr)
        if prev_addr == idc.BADADDR:
            break
            
        current_addr = prev_addr
        count += 1
        
        # Check if it is code
        if not idc.is_code(idc.get_full_flags(current_addr)):
            continue
            
        mnem = idc.print_insn_mnem(current_addr)
        if not mnem:
            continue
            
        mnem_lower = mnem.lower()
        
        # Check for control-flow boundary
        if mnem_lower in ['call', 'ret', 'retn'] or mnem_lower.startswith('j'):
            break
            
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
            for opnum in [1, 2]:
                op_type = idc.get_operand_type(current_addr, opnum)
                if op_type != -1:
                    op_str = idc.print_operand(current_addr, opnum)
                    source_regs.update(extract_registers(op_str))
                    
            # Check if it is a complete overwrite
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
                
    # Sort by address for printing
    slice_instructions = sorted(slice_instructions, key=lambda x: x[0])
    
    # print("  --- Slice ---")
    # for ea, disasm in slice_instructions:
    #     print(f"    {ea:#x}: {disasm}")
    # print("  -------------")
    
    return slice_instructions

def emulate_slice_for_val(remaining_eas, setcc_reg_family, setcc_val, jmp_reg, global_regs, machine, lifter, mdis, container, loc_db):
    if not remaining_eas:
        return setcc_val, global_regs
        
    # Build AsmCFG containing the slice instructions
    asmcfg = AsmCFG(loc_db)
    block = AsmBlock(loc_db, loc_db.gen_loc_key())
    for ea in remaining_eas:
        instr = mdis.dis_instr(ea)
        block.lines.append(instr)
    asmcfg.add_block(block)
    
    # Lift to IR
    ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
    
    # Initialize register state
    init_state = {}
    # Load all registers from global_regs to propagate state
    for reg_name, val in global_regs.items():
        init_state[ExprId(reg_name.upper(), 64)] = ExprInt(val, 64)
        
    # Force the setcc register family value (Case 1: 1, Case 2: 0)
    init_state[ExprId(setcc_reg_family.upper(), 64)] = ExprInt(setcc_val, 64)
    
    # Run the emulator
    engine = IDASymbolicExecutionEngine(lifter, container, init_state)
    engine.eval_updt_irblock(list(ircfg.blocks.values())[0])
    
    # Evaluate final destination register value
    final_val = engine.eval_expr(ExprId(jmp_reg.upper(), 64))
    
    # Read updated register values to propagate to global_regs
    GP_REGS = ['RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RSP', 'RBP', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15']
    updated_regs = {}
    for reg_name in GP_REGS:
        reg_id = ExprId(reg_name, 64)
        val = engine.symbols.read(reg_id)
        if isinstance(val, ExprInt):
            updated_regs[reg_name] = int(val)
        
    if isinstance(final_val, ExprInt):
        return int(final_val), updated_regs
    return None, updated_regs

def main():
    # Initialize Miasm elements using the binary file currently open in IDA
    loc_db = LocationDB()
    filepath = idc.get_input_file_path()
    with open(filepath, "rb") as f:
        container = Container.from_stream(f, loc_db)
        
    machine = Machine("x86_64")
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
    find_jmp_reg_addr(jumps_addr)
    
    # Sort jumps sequentially to ensure proper register propagation
    jumps_addr = sorted(jumps_addr, key=lambda x: x[0])
    
    # Global register state to propagate across jumps
    global_regs = {
        'RSP': 0x200000
    }
    
    print("\n=== RESOLVING AND COMMENTING INDIRECT JUMPS ===")
    for addr, reg in jumps_addr:
        # print(f"Analyzing {addr:#x}, JMP {reg}")
        
        # Get backward slice
        slice_instrs = backward_slice(addr, reg)
        
        # Find if slice has a setcc instruction (e.g. setl, setnz)
        setcc_idx = -1
        for i, (ea, _) in enumerate(slice_instrs):
            mnem = idc.print_insn_mnem(ea).lower()
            if mnem.startswith('set'):
                setcc_idx = i
                break
                
        if setcc_idx != -1:
            setcc_addr, _ = slice_instrs[setcc_idx]
            setcc_reg = idc.print_operand(setcc_addr, 0)
            setcc_reg_family = get_reg_family(setcc_reg)
            
            # Sub-slice instructions after setcc (excluding JMP instruction itself)
            remaining_eas = [ea for ea, _ in slice_instrs[setcc_idx + 1 : -1]]
            
            # Emulate case 1: setcc register = 1
            dest_true, regs_true = emulate_slice_for_val(
                remaining_eas, setcc_reg_family, 1, reg, global_regs,
                machine, lifter, mdis, container, loc_db
            )
            
            # Emulate case 2: setcc register = 0
            dest_false, regs_false = emulate_slice_for_val(
                remaining_eas, setcc_reg_family, 0, reg, global_regs,
                machine, lifter, mdis, container, loc_db
            )
            
            if dest_true is not None and dest_false is not None:
                print(f"  [+] Resolved destinations -> True: {dest_true:#x} | False: {dest_false:#x}")
                
                # Comment the resolved destinations at the JMP instruction
                comment = f"True: {dest_true:#x}\nFalse: {dest_false:#x}"
                idc.set_cmt(addr, comment, 0)
                # print(f"  [+] Added comment to {addr:#x}")
                
                # Patch in IDA database
                jmp_size = idc.get_item_size(addr)
                patch_size = (addr + jmp_size) - setcc_addr
                cond_name = idc.print_insn_mnem(setcc_addr).lower()[3:]
                success = patch_indirect_jump(setcc_addr, patch_size, dest_true, dest_false, cond_name)
                if success:
                    print(f"  [+] Patched jump block at {setcc_addr:#x} successfully.")
                
                # Propagate registers (e.g. from the True branch)
                global_regs.update(regs_true)
        #     else:
        #         print(f"  [-] Failed to resolve destinations dynamically.")
        # else:
        #     print(f"  [-] No setcc instruction found in slice.")

if __name__ == "__main__":
    main()