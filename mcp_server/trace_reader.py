"""
trace_reader.py - Standalone parser and analyzer for x64dbg .trace32 / .trace64 execution trace files.

Based on pinned x64dbg commit 9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87:
- docs/developers/tracefile.md
- src/gui/Src/Tracer/TraceFileReader.h / .cpp / Internal.h
- src/gui/Src/Tracer/TraceFileDump.h / .cpp
- src/gui/Src/Tracer/TraceFileSearch.h / .cpp
- src/dbg/TraceRecord.h / .cpp
"""

import os
import struct
import json
import bisect
import threading
import re
from typing import Dict, List, Tuple, Optional, Any, Set

MAX_HEADER_SIZE = 100 * 1024  # 100 KiB safety cap
MAX_MEMORY_OPERANDS = 32
PAGE_SIZE = 4096

# REGDUMP word counts
REGWORDS_COUNT_X64 = 172
REGWORDS_COUNT_X86 = 216

# Register names by index for x64
X64_REG_NAMES = {
    0: "rax",
    1: "rcx",
    2: "rdx",
    3: "rbx",
    4: "rsp",
    5: "rbp",
    6: "rsi",
    7: "rdi",
    8: "r8",
    9: "r9",
    10: "r10",
    11: "r11",
    12: "r12",
    13: "r13",
    14: "r14",
    15: "r15",
    16: "rip",
    17: "rflags",
    20: "dr0",
    21: "dr1",
    22: "dr2",
    23: "dr3",
    24: "dr6",
    25: "dr7",
}

# Register names by index for x86
X86_REG_NAMES = {
    0: "eax",
    1: "ecx",
    2: "edx",
    3: "ebx",
    4: "esp",
    5: "ebp",
    6: "esi",
    7: "edi",
    8: "eip",
    9: "eflags",
    13: "dr0",
    14: "dr1",
    15: "dr2",
    16: "dr3",
    17: "dr6",
    18: "dr7",
}


class TraceError(Exception):
    """Base exception for trace parsing/reading errors."""
    pass


class TraceHeader:
    def __init__(self, ver: int, arch: str, compression: str, hash_algo: str, hash_val: str, exe_path: str):
        self.version = ver
        self.arch = arch
        self.compression = compression
        self.hash_algorithm = hash_algo
        self.hash = hash_val
        self.executable_path = exe_path
        self.ptr_size = 8 if arch == "x64" else 4
        self.ptr_fmt = "<Q" if arch == "x64" else "<I"
        self.regwords_count = REGWORDS_COUNT_X64 if arch == "x64" else REGWORDS_COUNT_X86
        self.cip_index = 16 if arch == "x64" else 8
        self.csp_index = 4 if arch == "x64" else 4


class DecodedInstruction:
    def __init__(self, index: int, cip: int, thread_id: int, opcode: bytes, regwords: List[int],
                 mem_accesses: List[Tuple[int, int, int, int]]):
        self.index = index
        self.cip = cip
        self.thread_id = thread_id
        self.opcode = opcode
        self.regwords = regwords  # full snapshot of regwords at this instruction
        # mem_accesses: list of (addr, old_val, new_val, flag)
        self.mem_accesses = mem_accesses


class TracePage:
    """A contiguous chunk of instructions starting with a full checkpoint."""
    def __init__(self, start_index: int, file_offset: int, instruction_count: int):
        self.start_index = start_index
        self.file_offset = file_offset
        self.instruction_count = instruction_count
        self.instructions: Optional[List[DecodedInstruction]] = None


def disassemble_simple(opcode: bytes, cip: int, arch: str) -> str:
    """Fallback disassembler for x86/x64 instructions when capstone is unavailable."""
    if not opcode:
        return "??"
    b0 = opcode[0]
    
    # 64-bit REX prefix check
    prefix_len = 0
    if arch == "x64" and 0x40 <= b0 <= 0x4F and len(opcode) > 1:
        prefix_len = 1
        b0 = opcode[1]

    # Simple common mnemonics
    if b0 == 0x90:
        return "nop"
    elif b0 == 0xCC:
        return "int3"
    elif b0 in (0xC3, 0xC2):
        if b0 == 0xC2 and len(opcode) >= 3:
            imm = struct.unpack_from("<H", opcode, prefix_len + 1)[0]
            return f"ret {hex(imm)}"
        return "ret"
    elif b0 == 0xE8 and len(opcode) >= prefix_len + 5:
        # call rel32
        rel = struct.unpack_from("<i", opcode, prefix_len + 1)[0]
        target = (cip + len(opcode) + rel) & (0xFFFFFFFFFFFFFFFF if arch == "x64" else 0xFFFFFFFF)
        return f"call 0x{target:x}"
    elif b0 == 0xE9 and len(opcode) >= prefix_len + 5:
        # jmp rel32
        rel = struct.unpack_from("<i", opcode, prefix_len + 1)[0]
        target = (cip + len(opcode) + rel) & (0xFFFFFFFFFFFFFFFF if arch == "x64" else 0xFFFFFFFF)
        return f"jmp 0x{target:x}"
    elif b0 == 0xEB and len(opcode) >= prefix_len + 2:
        # jmp rel8
        rel = struct.unpack_from("<b", opcode, prefix_len + 1)[0]
        target = (cip + len(opcode) + rel) & (0xFFFFFFFFFFFFFFFF if arch == "x64" else 0xFFFFFFFF)
        return f"jmp 0x{target:x}"
    elif b0 == 0xFF and len(opcode) > prefix_len + 1:
        modrm = opcode[prefix_len + 1]
        reg = (modrm >> 3) & 7
        if reg == 2:
            return "call [indirect]"
        elif reg == 4:
            return "jmp [indirect]"
        elif reg == 0:
            return "inc"
        elif reg == 1:
            return "dec"
        elif reg == 6:
            return "push"
    elif 0x50 <= b0 <= 0x57:
        regs = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"] if arch == "x64" else ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
        return f"push {regs[b0 - 0x50]}"
    elif 0x58 <= b0 <= 0x5F:
        regs = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"] if arch == "x64" else ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
        return f"pop {regs[b0 - 0x58]}"
    elif b0 == 0x0F and len(opcode) > 1:
        b1 = opcode[1]
        if b1 == 0x05:
            return "syscall"
        elif b1 == 0x34:
            return "sysenter"
        elif 0x80 <= b1 <= 0x8F and len(opcode) >= 6:
            jccs = ["jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"]
            rel = struct.unpack_from("<i", opcode, 2)[0]
            target = (cip + len(opcode) + rel) & (0xFFFFFFFFFFFFFFFF if arch == "x64" else 0xFFFFFFFF)
            return f"{jccs[b1 - 0x80]} 0x{target:x}"

    # Default opcode hex display
    return f"db {opcode.hex()}"


class TraceFile:
    """Thread-safe reader and analyzer for a single x64dbg trace file."""
    def __init__(self, file_path: str):
        self.file_path = os.path.realpath(file_path)
        self.lock = threading.RLock()
        self._fp = None
        self.file_size = 0
        self.header: Optional[TraceHeader] = None
        self.length = 0  # Total instruction count
        self.pages: List[TracePage] = []  # sorted by start_index
        self.cached_pages: Dict[int, TracePage] = {}  # start_index -> TracePage
        self.max_cached_pages = 64
        self.is_valid = False
        
        # Historical memory dump structures (built on-demand or indexed)
        self._dump_lock = threading.RLock()
        self._dump_indexed = False
        # Map: address -> list of (trace_index, old_byte, new_byte)
        self._memory_timeline: Dict[int, List[Tuple[int, int, int]]] = {}
        # List of accessed addresses for fast range queries
        self._sorted_addresses: List[int] = []

        self._open_and_index()

    def _open_and_index(self):
        with self.lock:
            if not os.path.isfile(self.file_path):
                raise TraceError(f"Trace file does not exist: {self.file_path}")

            self.file_size = os.path.getsize(self.file_path)
            if self.file_size < 8:
                raise TraceError("File is too small to contain a trace header")

            self._fp = open(self.file_path, "rb")
            
            # 1. Read and validate header
            magic, header_len = struct.unpack("<II", self._fp.read(8))
            if magic != 0x43415254:  # 'TRAC'
                raise TraceError(f"Invalid magic: {hex(magic)} (expected 'TRAC')")

            if header_len > MAX_HEADER_SIZE:
                raise TraceError(f"Header info is too big: {header_len} bytes (max {MAX_HEADER_SIZE})")
            if header_len == 0:
                raise TraceError("Header info is empty")

            json_bytes = self._fp.read(header_len)
            if len(json_bytes) != header_len:
                raise TraceError("Truncated JSON header")

            try:
                header_obj = json.loads(json_bytes.decode("utf-8"))
            except Exception as e:
                raise TraceError(f"JSON header is corrupted: {e}")

            ver = header_obj.get("ver")
            if ver is None:
                raise TraceError("Version not found in header")
            if ver != 1:
                raise TraceError(f"Version not supported: {ver}")

            arch = header_obj.get("arch")
            if arch not in ("x64", "x86"):
                raise TraceError(f"Unsupported architecture: {arch}")

            compression = header_obj.get("compression", "")
            if compression != "":
                raise TraceError(f"Unsupported compression: {compression}")

            hash_algo = header_obj.get("hashAlgorithm", "")
            hash_val = header_obj.get("hash", "")
            exe_path = header_obj.get("path", "")

            self.header = TraceHeader(ver, arch, compression, hash_algo, hash_val, exe_path)

            # 2. Fast scan and index blocks
            ptr_size = self.header.ptr_size
            regwords_count = self.header.regwords_count
            
            index = 0
            last_page_start_index = 0

            while True:
                block_start_pos = self._fp.tell()
                btype_bytes = self._fp.read(1)
                if not btype_bytes:
                    break  # EOF reached cleanly

                block_type = btype_bytes[0]
                if block_type == 0:
                    flag_bytes = self._fp.read(3)
                    if len(flag_bytes) != 3:
                        raise TraceError("Truncated instruction block flags")

                    reg_changes, mem_accesses, flags_opcode = flag_bytes
                    has_tid = bool(flags_opcode & 0x80)
                    opcode_len = flags_opcode & 0x0F
                    if opcode_len == 0:
                        raise TraceError(f"Instruction at index {index} has zero opcode length")

                    skip_bytes = (4 if has_tid else 0) + opcode_len + reg_changes * (1 + ptr_size)
                    self._fp.seek(skip_bytes, os.SEEK_CUR)

                    if mem_accesses > 0:
                        memflags = self._fp.read(mem_accesses)
                        if len(memflags) != mem_accesses:
                            raise TraceError("Truncated memory flags")
                        skip_offset = sum(2 if (f & 1) else 3 for f in memflags)
                        self._fp.seek(skip_offset * ptr_size, os.SEEK_CUR)

                    # Check for page boundary
                    if reg_changes == regwords_count:
                        if self.pages:
                            # Finalize instruction count of previous page
                            self.pages[-1].instruction_count = index - last_page_start_index
                        self.pages.append(TracePage(index, block_start_pos, 0))
                        last_page_start_index = index

                    index += 1

                elif block_type >= 0x80:
                    # User-defined block
                    size_bytes = self._fp.read(4)
                    if len(size_bytes) != 4:
                        raise TraceError("Truncated user-defined block size")
                    block_size = struct.unpack("<I", size_bytes)[0]
                    self._fp.seek(block_size, os.SEEK_CUR)
                else:
                    raise TraceError(f"Unsupported block type: {block_type}")

            if self.pages:
                self.pages[-1].instruction_count = index - last_page_start_index

            self.length = index
            self.is_valid = True

    def close(self):
        with self.lock:
            if self._fp:
                try:
                    self._fp.close()
                except Exception:
                    pass
                self._fp = None
            self.cached_pages.clear()
            self._memory_timeline.clear()
            self._sorted_addresses.clear()
            self.is_valid = False

    def _get_page_for_index(self, index: int) -> Tuple[TracePage, int]:
        """Find the page containing `index` and its internal offset."""
        if not self.pages or index < 0 or index >= self.length:
            raise TraceError(f"Trace index out of bounds: {index} (length: {self.length})")

        # Binary search on self.pages
        page_indices = [p.start_index for p in self.pages]
        p_idx = bisect.bisect_right(page_indices, index) - 1
        if p_idx < 0 or p_idx >= len(self.pages):
            raise TraceError(f"Failed to find page for index {index}")

        page = self.pages[p_idx]
        offset_in_page = index - page.start_index
        return page, offset_in_page

    def _load_page(self, page: TracePage) -> List[DecodedInstruction]:
        """Decode all instructions in the page from disk into memory."""
        with self.lock:
            if page.start_index in self.cached_pages:
                return self.cached_pages[page.start_index].instructions

            if not self._fp or self._fp.closed:
                self._fp = open(self.file_path, "rb")

            self._fp.seek(page.file_offset)
            ptr_size = self.header.ptr_size
            ptr_fmt = self.header.ptr_fmt
            regwords_count = self.header.regwords_count
            cip_idx = self.header.cip_index

            decoded: List[DecodedInstruction] = []
            regwords = [0] * regwords_count
            last_tid = 0

            for i in range(page.instruction_count):
                idx = page.start_index + i
                btype = self._fp.read(1)[0]
                while btype >= 0x80:
                    bsize = struct.unpack("<I", self._fp.read(4))[0]
                    self._fp.seek(bsize, os.SEEK_CUR)
                    btype = self._fp.read(1)[0]

                if btype != 0:
                    raise TraceError(f"Unexpected block type during page decode: {btype}")

                reg_changes, mem_accesses, flags_opcode = self._fp.read(3)
                if flags_opcode & 0x80:
                    last_tid = struct.unpack("<I", self._fp.read(4))[0]

                opcode_len = flags_opcode & 0x0F
                opcode = self._fp.read(opcode_len)

                # Unpack registers
                if reg_changes > 0:
                    changed_pos = list(self._fp.read(reg_changes))
                    reg_content_bytes = self._fp.read(reg_changes * ptr_size)
                    reg_content = struct.unpack(f"<{reg_changes}{'Q' if ptr_size == 8 else 'I'}", reg_content_bytes)

                    last_pos = -1
                    for c_idx, c_rel in enumerate(changed_pos):
                        last_pos = last_pos + c_rel + 1
                        if 0 <= last_pos < regwords_count:
                            regwords[last_pos] = reg_content[c_idx]
                        else:
                            raise TraceError(f"Register change position out of bounds: {last_pos}")

                # Unpack memory accesses
                mem_list: List[Tuple[int, int, int, int]] = []
                if mem_accesses > 0:
                    memflags = list(self._fp.read(mem_accesses))
                    addr_bytes = self._fp.read(mem_accesses * ptr_size)
                    addrs = struct.unpack(f"<{mem_accesses}{'Q' if ptr_size == 8 else 'I'}", addr_bytes)

                    old_bytes = self._fp.read(mem_accesses * ptr_size)
                    old_vals = struct.unpack(f"<{mem_accesses}{'Q' if ptr_size == 8 else 'I'}", old_bytes)

                    new_vals = []
                    for m_idx in range(mem_accesses):
                        if (memflags[m_idx] & 1) == 0:
                            # Changed: read new value
                            val_bytes = self._fp.read(ptr_size)
                            new_val = struct.unpack(ptr_fmt, val_bytes)[0]
                            new_vals.append(new_val)
                        else:
                            # Unchanged
                            new_vals.append(old_vals[m_idx])

                    for m_idx in range(mem_accesses):
                        mem_list.append((addrs[m_idx], old_vals[m_idx], new_vals[m_idx], memflags[m_idx]))

                cip = regwords[cip_idx]
                decoded.append(DecodedInstruction(idx, cip, last_tid, opcode, list(regwords), mem_list))

            page.instructions = decoded

            # Manage page cache LRU
            if len(self.cached_pages) >= self.max_cached_pages:
                # Remove first inserted page
                oldest_key = next(iter(self.cached_pages))
                del self.cached_pages[oldest_key]
            self.cached_pages[page.start_index] = page

            return decoded

    def get_instruction(self, index: int) -> DecodedInstruction:
        page, offset = self._get_page_for_index(index)
        instructions = self._load_page(page)
        return instructions[offset]

    def _ensure_dump_indexed(self):
        """Index all historical memory accesses and opcodes for memory reconstruction."""
        with self._dump_lock:
            if self._dump_indexed:
                return

            ptr_size = self.header.ptr_size
            ptr_fmt = self.header.ptr_fmt

            # Scan through all pages and instructions
            for page in self.pages:
                insts = self._load_page(page)
                for inst in insts:
                    idx = inst.index
                    # 1. Record memory accesses
                    for addr, old_val, new_val, _ in inst.mem_accesses:
                        old_bytes = struct.pack(ptr_fmt, old_val)
                        new_bytes = struct.pack(ptr_fmt, new_val)
                        for b in range(ptr_size):
                            byte_addr = addr + b
                            if byte_addr not in self._memory_timeline:
                                self._memory_timeline[byte_addr] = []
                            self._memory_timeline[byte_addr].append((idx, old_bytes[b], new_bytes[b]))

                    # 2. Record opcode bytes at CIP
                    for b in range(len(inst.opcode)):
                        byte_addr = inst.cip + b
                        op_byte = inst.opcode[b]
                        if byte_addr not in self._memory_timeline:
                            self._memory_timeline[byte_addr] = []
                        self._memory_timeline[byte_addr].append((idx, op_byte, op_byte))

            self._sorted_addresses = sorted(self._memory_timeline.keys())
            self._dump_indexed = True

    def read_memory(self, addr: int, size: int, trace_index: int) -> Tuple[bytes, int, int]:
        """Reconstruct historical memory at `trace_index` following TraceFileDump::getBytes semantics."""
        self._ensure_dump_indexed()
        result = bytearray(size)
        known_count = 0
        unknown_count = 0

        for i in range(size):
            target_addr = addr + i
            timeline = self._memory_timeline.get(target_addr)
            if not timeline:
                # Byte was never accessed in trace: filled with zero
                result[i] = 0
                unknown_count += 1
                continue

            # Bisect timeline to find access relative to trace_index
            # timeline is sorted by trace_index ascending
            indices = [entry[0] for entry in timeline]
            pos = bisect.bisect_right(indices, trace_index) - 1

            if pos >= 0:
                # Access happened before or at trace_index
                acc_idx, old_b, new_b = timeline[pos]
                if trace_index > acc_idx:
                    result[i] = new_b
                else:
                    result[i] = old_b  # At the instruction index, old data is preferred
                known_count += 1
            else:
                # Access happened after trace_index: take oldData before first modification
                acc_idx, old_b, new_b = timeline[0]
                result[i] = old_b
                known_count += 1

        return bytes(result), known_count, unknown_count

    def get_references(self, start_addr: int, end_addr: int, max_results: int = 100) -> List[int]:
        """Find trace indices that accessed memory in [start_addr, end_addr]."""
        self._ensure_dump_indexed()
        if start_addr > end_addr:
            start_addr, end_addr = end_addr, start_addr

        # Find addresses in range via bisect on _sorted_addresses
        start_pos = bisect.bisect_left(self._sorted_addresses, start_addr)
        end_pos = bisect.bisect_right(self._sorted_addresses, end_addr)

        ref_indices: Set[int] = set()
        for idx in range(start_pos, end_pos):
            address = self._sorted_addresses[idx]
            for t_idx, _, _ in self._memory_timeline[address]:
                ref_indices.add(t_idx)

        sorted_refs = sorted(ref_indices)
        return sorted_refs[:max_results]

    def search_address(self, start_addr: int, end_addr: Optional[int] = None, max_results: int = 100) -> List[DecodedInstruction]:
        if end_addr is None:
            end_addr = start_addr
        if start_addr > end_addr:
            start_addr, end_addr = end_addr, start_addr

        results = []
        for page in self.pages:
            insts = self._load_page(page)
            for inst in insts:
                if start_addr <= inst.cip <= end_addr:
                    results.append(inst)
                    if len(results) >= max_results:
                        return results
        return results

    def search_memory(self, pattern_str: str, max_results: int = 100) -> List[Dict[str, Any]]:
        """Search memory pattern with wildcards (e.g. '48 89 ?? 55')."""
        self._ensure_dump_indexed()
        
        # Parse hex pattern with '?' wildcards
        pattern_tokens = pattern_str.strip().split()
        if not pattern_tokens:
            return []

        pattern_len = len(pattern_tokens)
        data = []
        mask = []
        for tok in pattern_tokens:
            if tok in ("??", "?"):
                data.append(0)
                mask.append(0)
            elif len(tok) == 2:
                d = 0
                m = 0
                # High nibble
                if tok[0] == '?':
                    m |= 0x00
                else:
                    d |= (int(tok[0], 16) << 4)
                    m |= 0xF0
                # Low nibble
                if tok[1] == '?':
                    m |= 0x00
                else:
                    d |= int(tok[1], 16)
                    m |= 0x0F
                data.append(d)
                mask.append(m)
            else:
                raise TraceError(f"Invalid pattern token: '{tok}'")

        # Find matches across contiguous memory regions
        # Check consecutive addresses in _sorted_addresses
        matches = []
        for i in range(len(self._sorted_addresses) - pattern_len + 1):
            base_addr = self._sorted_addresses[i]
            # Check if subsequent addresses are contiguous
            is_contiguous = True
            for k in range(1, pattern_len):
                if self._sorted_addresses[i + k] != base_addr + k:
                    is_contiguous = False
                    break
            if not is_contiguous:
                continue

            # Check match at index 0 (initial state) and at last state
            # A pattern matches if there exists an instruction index where all bytes match
            start_idx = self._memory_timeline[base_addr][0][0]
            end_idx = self._memory_timeline[base_addr][-1][0]
            
            # Read reconstructed memory at end_idx
            mem_bytes, known, _ = self.read_memory(base_addr, pattern_len, end_idx)
            if known == pattern_len:
                matched = True
                for b_idx in range(pattern_len):
                    if (mem_bytes[b_idx] & mask[b_idx]) != (data[b_idx] & mask[b_idx]):
                        matched = False
                        break
                if matched:
                    matches.append({
                        "address": hex(base_addr),
                        "start_index": start_idx,
                        "end_index": end_idx
                    })
                    if len(matches) >= max_results:
                        break

        return matches

    def find_calls(self, max_results: int = 100, intermodular: bool = False) -> List[Dict[str, Any]]:
        """Search trace for call instructions and resolve destinations."""
        calls = []
        ptr_size = self.header.ptr_size
        arch = self.header.arch

        for page in self.pages:
            insts = self._load_page(page)
            for inst in insts:
                opcode = inst.opcode
                if not opcode:
                    continue

                b0 = opcode[0]
                prefix_len = 0
                if arch == "x64" and 0x40 <= b0 <= 0x4F and len(opcode) > 1:
                    prefix_len = 1
                    b0 = opcode[1]

                is_call = False
                is_direct = False
                target = None

                if b0 == 0xE8 and len(opcode) >= prefix_len + 5:
                    # Direct CALL rel32
                    is_call = True
                    is_direct = True
                    rel = struct.unpack_from("<i", opcode, prefix_len + 1)[0]
                    target = (inst.cip + len(opcode) + rel) & (0xFFFFFFFFFFFFFFFF if arch == "x64" else 0xFFFFFFFF)

                elif b0 == 0xFF and len(opcode) > prefix_len + 1:
                    modrm = opcode[prefix_len + 1]
                    reg = (modrm >> 3) & 7
                    if reg == 2:  # CALL r/m
                        is_call = True
                        is_direct = False
                        mod = (modrm >> 6) & 3
                        rm = modrm & 7
                        if mod == 3:
                            # Register operand: lookup from regwords
                            # Map rm to regwords index
                            if arch == "x64":
                                # REX.B affects rm
                                rex_b = 1 if (prefix_len > 0 and (opcode[0] & 1)) else 0
                                reg_id = rm + (8 if rex_b else 0)
                                if reg_id < 16:
                                    target = inst.regwords[reg_id]
                            else:
                                if rm < 8:
                                    target = inst.regwords[rm]
                        else:
                            # Memory operand: lookup from recorded memory accesses
                            if inst.mem_accesses:
                                target = inst.mem_accesses[0][1]  # oldMemory[0]

                if is_call:
                    disasm_text = disassemble_simple(opcode, inst.cip, arch)
                    is_inter = False
                    if target is not None:
                        # Intermodular check: if target and CIP belong to different 4KB pages
                        is_inter = (inst.cip & ~(PAGE_SIZE - 1)) != (target & ~(PAGE_SIZE - 1))

                    if intermodular and not is_inter:
                        continue

                    calls.append({
                        "index": inst.index,
                        "address": hex(inst.cip),
                        "thread_id": inst.thread_id,
                        "opcode": opcode.hex(),
                        "disassembly": disasm_text,
                        "destination": hex(target) if target is not None else None,
                        "is_direct": is_direct,
                        "is_intermodular": is_inter
                    })

                    if len(calls) >= max_results:
                        return calls

        return calls


class TraceSessionManager:
    """Manages active trace file sessions, canonicalizing paths and enforcing bounds."""
    def __init__(self):
        self._lock = threading.RLock()
        self._traces: Dict[str, TraceFile] = {}
        self._path_to_id: Dict[str, str] = {}
        self._counter = 0

    def open_trace(self, path: str) -> Tuple[str, TraceFile]:
        canon_path = os.path.realpath(path)
        with self._lock:
            if canon_path in self._path_to_id:
                tid = self._path_to_id[canon_path]
                trace = self._traces[tid]
                if trace.is_valid:
                    return tid, trace

            # Create new trace
            self._counter += 1
            tid = f"trace_{self._counter}"
            trace = TraceFile(canon_path)
            self._traces[tid] = trace
            self._path_to_id[canon_path] = tid
            return tid, trace

    def get_trace(self, tid: str) -> TraceFile:
        with self._lock:
            trace = self._traces.get(tid)
            if not trace or not trace.is_valid:
                raise TraceError(f"Trace session '{tid}' not found or closed")
            return trace

    def close_trace(self, tid: str) -> bool:
        with self._lock:
            trace = self._traces.pop(tid, None)
            if trace:
                self._path_to_id.pop(trace.file_path, None)
                trace.close()
                return True
            return False

    def close_all(self):
        with self._lock:
            for trace in self._traces.values():
                trace.close()
            self._traces.clear()
            self._path_to_id.clear()


# Global singleton instance
trace_sessions = TraceSessionManager()
