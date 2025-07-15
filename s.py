#!/usr/bin/env python3

import argparse
import csv
import json
import logging
import re
import struct
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

# Global logging configuration
LOG_DIR = None
logger = logging.getLogger(__name__)

class Config:
    """Configuration for bootloader analysis."""
    EMMC_VENDORS = {
        b'\x15\x01\x00': 'Samsung',
        b'\x70\x01\x00': 'SK Hynix',
        b'\x90\x01\x4A': 'Hynix',
        b'\x45\x01\x00': 'Sandisk',
        b'\xFE\x01\x4A': 'Micron',
        b'\x03\x00\x44': 'Unknown Vendor (0x030044)',  # Added from log data
    }
    PATTERNS = {
        'MTK_BLOADER_INFO': b'MTK_BLOADER_INFO',
        'MTK_BIN': b'MTK_BIN',
        'ARM_CODE_NOP': b'\x00\xF0\x20\xE3',
        'STRING': lambda x: len(x) > 4 and all(32 <= c < 127 for c in x),
        'POTENTIAL_PTR': lambda x, file_size: len(x) == 4 and 0x1000 <= int.from_bytes(x, 'little') < file_size,
    }
    ELEMENT_SIZE = 188
    HEADER_SIZE = 112
    MAX_DRAM_SIZE_MB = 16384
    MIN_FILE_SIZE = 128
    MAX_CODE_SECTION_SIZE = 4096

def decode_bytes(data: bytes) -> str:
    """Decode bytes to string, replacing non-printable characters.

    Args:
        data: Bytes to decode.

    Returns:
        Decoded string with non-printable characters replaced.
    """
    return ''.join(chr(b) if 32 <= b < 127 else '.' for b in data).strip('.')

def interpret_emi_cona_val(emi_cona_val: int) -> Dict[str, Any]:
    """Interpret EMI_CONA register value.

    Args:
        emi_cona_val: EMI_CONA register value.

    Returns:
        Dictionary with dual rank, bus width, and burst settings.
    """
    dual_rank = bool(emi_cona_val & 0x80000000)
    bus_width = 16 if emi_cona_val & 0x00000004 else 32
    burst_enabled = bool(emi_cona_val & 0x00000001)
    return {
        'dual_rank': dual_rank,
        'bus_width': bus_width,
        'burst_enabled': burst_enabled
    }

def interpret_dram_rank_size(rank_sizes: Tuple[int, ...]) -> List[str]:
    """Interpret DRAM rank sizes into logical units.

    Args:
        rank_sizes: Tuple of DRAM rank sizes in bytes.

    Returns:
        List of formatted size strings (e.g., "1 GB", "512 MB", "Disabled").
    """
    sizes = []
    for size in rank_sizes:
        if size == 0:
            sizes.append("Disabled")
        else:
            mb = size // (1024 * 1024)
            sizes.append(f"{mb // 1024} GB" if mb >= 1024 else f"{mb} MB")
    return sizes

def decode_emmc_id(emmc_id: bytes, emmc_id_len: int) -> Dict[str, Any]:
    """Decode eMMC ID with manufacturer info and additional details.

    Args:
        emmc_id: eMMC ID bytes.
        emmc_id_len: Length of the eMMC ID.

    Returns:
        Dictionary with vendor, model, raw data, and details.
    """
    if not 0 <= emmc_id_len <= 16:
        logger.warning(f"Invalid eMMC ID length {emmc_id_len}, treating as 0")
        emmc_id_len = 0
    
    vendor_prefix = emmc_id[:3]
    vendor = Config.EMMC_VENDORS.get(vendor_prefix, f'Unknown (0x{vendor_prefix.hex().upper()})')
    model_bytes = emmc_id[3:emmc_id_len] if emmc_id_len > 0 else b''
    model_str = model_bytes.decode('ascii', errors='ignore').strip()
    model = model_str if all(c.isprintable() for c in model_str) and model_str else model_bytes.hex().upper()
    
    details = {}
    if vendor.startswith('Unknown') and emmc_id_len > 0 and any(emmc_id[:emmc_id_len]):
        details['possible_id'] = decode_bytes(emmc_id[:emmc_id_len])
    if vendor != 'Unknown' and len(model_bytes) >= 2:
        details['revision'] = model_bytes[-2:].hex().upper()
        details['capacity_hint'] = 'Unknown'
    
    return {
        'vendor': vendor,
        'model': model,
        'raw': emmc_id[:16].hex().upper(),
        'details': details
    }

def decode_reserved(reserved: bytes) -> Dict[str, Any]:
    """Decode reserved field for strings or pointers.

    Args:
        reserved: Reserved field bytes.

    Returns:
        Dictionary with analysis results.
    """
    analysis = {
        'strings': [s.decode('ascii') for s in re.findall(b'[\x20-\x7e]{5,}', reserved)],
        'pointers': [],
        'insights': []
    }
    for i in range(0, len(reserved) - 3, 4):
        val = struct.unpack_from('<I', reserved, i)[0]
        if 0x1000 <= val < 0x1FFFFF:
            analysis['pointers'].append(f"0x{val:08X}")
    if len(set(reserved)) < 5:
        analysis['insights'].append("Low variety: Possible repeating pattern or table")
    elif len(set(reserved)) > 20:
        analysis['insights'].append("High entropy: Possible encrypted data")
    else:
        analysis['insights'].append("Possible string or identifier")
    return analysis

def disassemble_code(data: bytes, offset: int, max_instructions: int = 10) -> Dict[str, Any]:
    """Disassemble code section with ARM and Thumb mode attempts.

    Args:
        data: Data to disassemble.
        offset: Starting offset for disassembly.
        max_instructions: Maximum number of instructions to disassemble.

    Returns:
        Dictionary with disassembled instructions, functions, and insights.
    """
    if not CAPSTONE_AVAILABLE:
        return {
            'instructions': [f"Disassembly unavailable: Install capstone (pip install capstone)"],
            'functions': [],
            'insights': []
        }
    if len(data) < 4 or offset % 4 != 0:
        return {
            'instructions': ["Invalid alignment or insufficient data for disassembly"],
            'functions': [],
            'insights': []
        }
    try:
        modes = [(CS_MODE_ARM, "ARM"), (CS_MODE_THUMB, "Thumb")]
        best_result = {'instructions': [], 'functions': [], 'insights': [], 'valid_count': 0}
        file_size = len(data) + offset  # Approximate file size for pointer validation
        for mode, mode_name in modes:
            md = Cs(CS_ARCH_ARM, mode)
            instructions = []
            func_starts = []
            branch_targets = set()
            valid_count = 0
            for i, (address, size, mnemonic, op_str) in enumerate(md.disasm_lite(data, offset)):
                if i >= max_instructions:
                    instructions.append("... (more instructions available)")
                    break
                if mnemonic != 'andeq' or op_str != 'r0, r0, r0':
                    valid_count += 1
                instr = f"0x{address:08X}: {mnemonic} {op_str}"
                instructions.append(instr)
                if i == 0 and mnemonic in ('push', 'stmfd', 'sub sp'):
                    func_starts.append(f"0x{address:08X} ({mode_name})")
                if mnemonic.startswith('b') and op_str.startswith('0x'):
                    try:
                        target = int(op_str, 16)
                        if 0x1000 <= target < file_size:
                            branch_targets.add(target)
                    except ValueError:
                        pass
            if valid_count > best_result['valid_count']:
                best_result = {
                    'instructions': instructions,
                    'functions': func_starts,
                    'insights': [f"Disassembled in {mode_name} mode"],
                    'valid_count': valid_count
                }
                if branch_targets:
                    best_result['functions'].extend(f"0x{t:08X} ({mode_name})" for t in branch_targets)
                    best_result['insights'].append(f"Branch targets detected: {', '.join(f'0x{t:08X}' for t in branch_targets)}")
                if func_starts:
                    best_result['insights'].append(f"Potential function entry in {mode_name} mode at {func_starts[0]}")
        if not best_result['instructions']:
            best_result['instructions'] = ["No valid instructions found"]
        elif best_result['valid_count'] >= 5:
            best_result['insights'].append("Significant code section detected. Review for bootloader logic.")
        return best_result
    except Exception as e:
        return {
            'instructions': [f"Disassembly error: {e}"],
            'functions': [],
            'insights': []
        }

def validate_element(element: Dict, offset: int, file_size: int) -> List[str]:
    """Validate element data with improved context.

    Args:
        element: Element dictionary to validate.
        offset: Offset of the element in the file.
        file_size: Total file size for validation.

    Returns:
        List of warning messages for invalid fields.
    """
    warnings = []
    if 'raw_data' in element:
        return [f"Element at offset 0x{offset:X} is corrupted or unparsed"]
    
    emmc_id_len = min(element['emmc_id_len'], 16) if 0 <= element['emmc_id_len'] <= 16 else 0
    fw_id_len = min(element['fw_id_len'], 8) if 0 <= element['fw_id_len'] <= 8 else 0
    
    if element['emmc_id_len'] != emmc_id_len:
        warnings.append(f"Invalid eMMC ID length at offset 0x{offset:X}: {element['emmc_id_len']} (capped at {emmc_id_len})")
    if element['fw_id_len'] != fw_id_len:
        warnings.append(f"Invalid firmware ID length at offset 0x{offset:X}: {element['fw_id_len']} (capped at {fw_id_len})")
    
    total_mb = sum(size // (1024 * 1024) for size in element['dram_rank_size'])
    if total_mb > Config.MAX_DRAM_SIZE_MB:
        warnings.append(f"Unrealistic total DRAM size at offset 0x{offset:X}: {total_mb} MB")
    if total_mb == 0 and element['emi_cona_val'] == 0 and element['dramc_actim_val'] == 0:
        warnings.append(f"Element at offset 0x{offset:X} appears empty or disabled")
    if element['type'] not in (0x203, 0) and not (0x100 <= element['type'] <= 0xFFFF):
        warnings.append(f"Unusual memory type at offset 0x{offset:X}: 0x{element['type']:X}")
    if any(element['reserved']) and len(set(element['reserved'])) < 5:
        warnings.append(f"Reserved field at offset 0x{offset:X} has low entropy, possible padding or corruption")
    return warnings

def read_element(data: bytes, offset: int, file_size: int) -> Tuple[int, Dict]:
    """Read a single element with corruption detection.

    Args:
        data: Full data buffer.
        offset: Starting offset of the element.
        file_size: Total file size for validation.

    Returns:
        Tuple of (new offset, element dictionary).
    """
    try:
        if offset + Config.ELEMENT_SIZE > len(data):
            raise ValueError(f"Insufficient data for element at 0x{offset:X} (need {Config.ELEMENT_SIZE} bytes)")
        
        cur_pos = offset
        element = {'_offset': offset}
        fields = struct.unpack_from('<4I', data, cur_pos)
        element['sub_version'], element['type'], emmc_id_len, fw_id_len = fields
        
        # Cap invalid lengths
        element['emmc_id_len'] = min(max(emmc_id_len, 0), 16)
        element['fw_id_len'] = min(max(fw_id_len, 0), 8)
        if emmc_id_len != element['emmc_id_len'] or fw_id_len != element['fw_id_len']:
            logger.warning(f"Capped invalid lengths at offset 0x{offset:X}: eMMC={emmc_id_len} to {element['emmc_id_len']}, FW={fw_id_len} to {element['fw_id_len']}")
        
        cur_pos += 16
        element['emmc_id'] = data[cur_pos:cur_pos+16]
        cur_pos += 16
        element['fw_id'] = data[cur_pos:cur_pos+8]
        cur_pos += 8
        dram_fields = struct.unpack_from('<17I', data, cur_pos)
        element['emi_cona_val'], element['dramc_drvctl0_val'], element['dramc_drvctl1_val'], element['dramc_actim_val'], \
        element['dramc_gddr3ctl1_val'], element['dramc_conf1_val'], element['dramc_ddr2ctl_val'], element['dramc_test2_3_val'], \
        element['dramc_conf2_val'], element['dramc_pd_ctrl_val'], element['dramc_padctl3_val'], element['dramc_dqodly_val'], \
        element['dramc_addr_output_dly'], element['dramc_clk_output_dly'], element['dramc_actim1_val'], element['dramc_misctl0_val'], \
        element['dramc_actim05t_val'] = dram_fields
        cur_pos += 68
        element['dram_rank_size'] = struct.unpack_from('<4I', data, cur_pos)
        cur_pos += 16
        element['reserved'] = data[cur_pos:cur_pos+40]
        cur_pos += 40
        lpddr3_regs = struct.unpack_from('<6I', data, cur_pos)
        element['lpddr3_mode_reg1'], element['lpddr3_mode_reg2'], element['lpddr3_mode_reg3'], \
        element['lpddr3_mode_reg5'], element['lpddr3_mode_reg10'], element['lpddr3_mode_reg63'] = lpddr3_regs
        cur_pos += 24
        
        # Early detection of empty or corrupted element
        if all(v == 0 for v in element['dram_rank_size'] + (element['emi_cona_val'], element['dramc_actim_val'])):
            logger.warning(f"Empty or disabled element at offset 0x{offset:X}")
            element['status'] = 'Empty or Disabled'
        
        return cur_pos, element
    except (struct.error, ValueError) as e:
        logger.error(f"Failed to parse element at offset 0x{offset:X}: {e}")
        element = {'_offset': offset, 'raw_data': data[offset:min(offset + Config.ELEMENT_SIZE, len(data))].hex().upper(), 'status': 'Corrupted'}
        return offset + Config.ELEMENT_SIZE, element

def extract_section(data: bytes, start: int, size: int, output_dir: Path, name: str, analyze: bool = False, file_size: int = 0) -> Dict[str, Any]:
    """Extract a data section to a file with optional analysis.

    Args:
        data: Full data buffer.
        start: Start offset of the section.
        size: Size of the section.
        output_dir: Directory to save the extracted file.
        name: Name of the section.
        analyze: Whether to analyze the section (e.g., for strings or code).
        file_size: Total file size for validation.

    Returns:
        Dictionary with section metadata and analysis.
    """
    if size <= 0:
        logger.warning(f"Skipping section {name} at 0x{start:X} with invalid size {size}")
        return {'path': None, 'size': 0, 'status': 'Invalid Size'}
    
    if start + size > len(data):
        logger.warning(f"Section {name} at 0x{start:X} exceeds file size, truncating to {len(data) - start} bytes")
        size = len(data) - start
    
    section = data[start:start + size]
    output_path = output_dir / f"{name}_{start:08X}_{size}.bin"
    with output_path.open('wb') as f:
        f.write(section)
    logger.info(f"Extracted section '{name}' at 0x{start:X} (size: {size} bytes) to {output_path}")
    
    analysis = {'path': str(output_path), 'size': size}
    if analyze and size > 4:
        analysis['strings'] = [s for s in re.findall(b'[\x20-\x7e]{5,}', section)]
        analysis.update(disassemble_code(section, start, max_instructions=10))
        analysis['reserved'] = {}
    return analysis

def analyze_remaining_data(data: bytes, start: int, output_dir: Path, file_size: int, max_size: int = 1024*1024) -> Dict[str, Any]:
    """Analyze remaining data for strings, code, and pointers.

    Args:
        data: Remaining data buffer.
        start: Starting offset of the remaining data.
        output_dir: Directory to save extracted sections.
        file_size: Total file size for validation.
        max_size: Maximum size to analyze to prevent performance issues.

    Returns:
        Dictionary with analysis results.
    """
    if len(data) > max_size:
        logger.warning(f"Remaining data size ({len(data)} bytes) exceeds analysis limit ({max_size} bytes), truncating")
        data = data[:max_size]
    
    analysis = {
        'offset': f"0x{start:X}",
        'size': len(data),
        'strings': [],
        'code_sections': [],
        'pointers': [],
        'insights': [],
        'entropy': sum(data.count(b) for b in set(data)) / len(data) if data else 0
    }
    
    # String detection
    analysis['strings'] = [f"0x{start + m.start():X}: {m.group().decode('ascii')}"
                          for m in re.finditer(b'[\x20-\x7e]{5,}', data)]
    
    # Pointer detection
    for i in range(0, len(data) - 3, 4):
        val = struct.unpack_from('<I', data, i)[0]
        if Config.PATTERNS['POTENTIAL_PTR'](data[i:i+4], file_size):
            analysis['pointers'].append(f"0x{start + i:X}: 0x{val:08X}")
    
    # Code detection
    if CAPSTONE_AVAILABLE:
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        code_start = None
        instructions = []
        for i in range(0, len(data) - 3, 4):
            if i + 4 > len(data):
                break
            chunk = data[i:i+4]
            if (i + start) % 4 != 0:  # Ensure 4-byte alignment
                continue
            disasm_result = list(md.disasm(chunk, start + i))
            if disasm_result and not all(ins.mnemonic == 'andeq' and ins.op_str == 'r0, r0, r0' for ins in disasm_result):
                if code_start is None:
                    code_start = start + i
                instructions.extend(f"0x{a:08X}: {m} {o}" for a, s, m, o in md.disasm_lite(chunk, start + i))
            elif code_start is not None and instructions:
                section_size = min(i - (code_start - start), Config.MAX_CODE_SECTION_SIZE)
                if section_size > 0:
                    disasm_analysis = disassemble_code(data[code_start - start:code_start - start + section_size], code_start, max_instructions=10)
                    analysis['code_sections'].append({
                        'offset': f"0x{code_start:X}",
                        'size': section_size,
                        'instructions': disasm_analysis['instructions'][:10],
                        'functions': disasm_analysis['functions'],
                        'insights': disasm_analysis['insights']
                    })
                    extract_section(data[code_start - start:code_start - start + section_size], code_start, section_size, output_dir, "CODE_SECTION", analyze=False, file_size=file_size)
                code_start = None
                instructions = []
        
        if instructions and code_start is not None:
            section_size = min(len(data) - (code_start - start), Config.MAX_CODE_SECTION_SIZE)
            if section_size > 0:
                disasm_analysis = disassemble_code(data[code_start - start:code_start - start + section_size], code_start, max_instructions=10)
                analysis['code_sections'].append({
                    'offset': f"0x{code_start:X}",
                    'size': section_size,
                    'instructions': disasm_analysis['instructions'][:10],
                    'functions': disasm_analysis['functions'],
                    'insights': disasm_analysis['insights']
                })
                extract_section(data[code_start - start:code_start - start + section_size], code_start, section_size, output_dir, "CODE_SECTION", analyze=False, file_size=file_size)
    
    if analysis['entropy'] > 0.9:
        analysis['insights'].append("High entropy detected: Possible encrypted or compressed section")
    if analysis['pointers']:
        analysis['insights'].append(f"Pointers found: May reference offsets within file (size: {file_size} bytes)")
    if analysis['code_sections']:
        analysis['insights'].append("Executable code detected: Potential bootloader logic or initialization routines")
    
    return analysis

def generate_flash_tool_config(elements: List[Dict], output_dir: Path) -> None:
    """Generate SP Flash Tool configuration file.

    Args:
        elements: List of parsed elements.
        output_dir: Directory to save the configuration file.
    """
    config_path = output_dir / "flash_tool_memory_config.txt"
    with config_path.open('w', encoding='utf-8') as f:
        f.write("# SP Flash Tool Memory Configuration\n")
        f.write("# Generated by MTK Bootloader Analysis\n\n")
        for i, element in enumerate(elements):
            if element.get('status') in ('Corrupted', 'Empty or Disabled'):
                continue
            f.write(f"# Element {i} at offset {element['offset']}\n")
            f.write(f"eMMC Vendor: {element['emmc']['vendor']}\n")
            f.write(f"eMMC Model: {element['emmc']['model']}\n")
            f.write(f"Memory Type: {element['memory_type']}\n")
            f.write(f"DRAM Ranks: {', '.join(element['dram_rank_size'])} (Total: {element['total_dram_size_mb']} MB)\n")
            f.write(f"Dual Rank: {element['emi_cona']['dual_rank']}\n")
            f.write(f"Bus Width: {element['emi_cona']['bus_width']} bits\n")
            f.write(f"Burst Enabled: {element['emi_cona']['burst_enabled']}\n")
            f.write(f"Estimated Frequency: {element['estimated_frequency']}\n")
            f.write(f"EMI_CONA: 0x{element['emi_cona_val']:08X}\n")
            f.write(f"DRAMC_ACTIM: 0x{element['dramc_actim_val']:08X}\n")
            f.write("\n")
    logger.info(f"Generated SP Flash Tool config at {config_path}")

def export_markdown(result: Dict[str, Any], output_dir: Path) -> None:
    """Export analysis result to a Markdown file.

    Args:
        result: Analysis result dictionary.
        output_dir: Directory to save the Markdown file.
    """
    md_path = output_dir / "analysis.md"
    with md_path.open('w', encoding='utf-8') as f:
        f.write("# MediaTek Bootloader Analysis\n\n")
        f.write(f"**File Size**: {result['file_size']} bytes\n\n")
        f.write("## Header\n")
        for key, value in result['header'].items():
            if key.startswith('_'):
                continue
            f.write(f"- **{key.replace('_', ' ').title()}**: {value}\n")
        
        f.write("\n## Elements\n")
        for i, element in enumerate(result['elements']):
            if element.get('status') in ('Corrupted', 'Empty or Disabled'):
                f.write(f"\n### Element {i} ({element.get('status')})\n")
                f.write(f"- **Offset**: {element['offset']}\n")
                if 'raw_data' in element:
                    f.write(f"- **Raw Data**: {element['raw_data']}\n")
                continue
            f.write(f"\n### Element {i}\n")
            f.write(f"- **Offset**: {element['offset']}\n")
            f.write(f"- **Type**: {element['memory_type']}\n")
            f.write(f"- **eMMC ID**: {element['emmc']['vendor']} (Raw: {element['emmc']['raw']}, Rev: {element['emmc']['details'].get('revision', 'N/A')})\n")
            f.write(f"- **Firmware ID**: {element['firmware_id']}\n")
            f.write(f"- **EMI_CONA_VAL**: 0x{element['emi_cona_val']:08X} (Dual Rank: {element['emi_cona']['dual_rank']}, Bus Width: {element['emi_cona']['bus_width']} bits, Burst: {'Enabled' if element['emi_cona']['burst_enabled'] else 'Disabled'})\n")
            f.write(f"- **DRAMC_ACTIM_VAL**: 0x{element['dramc_actim_val']:08X} (Est. Freq: {element['estimated_frequency']})\n")
            f.write(f"- **DRAM Rank Size**: {', '.join(element['dram_rank_size'])} (Total: {element['total_dram_size_mb']} MB)\n")
            if element['reserved']['strings'] or element['reserved']['pointers']:
                f.write(f"- **Reserved**: {element['reserved']['insights'][0] if element['reserved']['insights'] else 'None'}\n")
                if element['reserved']['strings']:
                    f.write("  - **Strings**: " + ", ".join(element['reserved']['strings']) + "\n")
                if element['reserved']['pointers']:
                    f.write("  - **Pointers**: " + ", ".join(element['reserved']['pointers']) + "\n")
            f.write(f"- **Recommendations**: {', '.join(element['recommendations'])}\n")
        
        f.write("\n## Analysis Summary\n")
        f.write(f"- **Supported eMMC Vendors**: {', '.join(result['analysis']['emmc_vendors'])}\n")
        f.write(f"- **Memory Types**: {', '.join(result['analysis']['memory_types'])}\n")
        f.write(f"- **Total Elements**: {result['analysis']['total_elements']}\n")
        f.write(f"- **Valid Elements**: {result['analysis']['valid_elements']}\n")
        f.write(f"- **Empty or Disabled Elements**: {result['analysis']['empty_elements']}\n")
        f.write(f"- **Corrupted Elements**: {result['analysis']['corrupted_elements']}\n")
        f.write("\n### DRAM Size Distribution\n")
        for size, count in sorted(result['analysis']['dram_size_distribution'].items()):
            unit = "MB" if size < 1024 else "GB"
            display_size = size if unit == "MB" else size // 1024
            f.write(f"- {display_size} {unit}: {'*' * count} ({count} elements)\n")
        
        f.write("\n### Extracted Sections\n")
        for section in result['additional_sections']:
            if 'path' in section and section['path']:
                f.write(f"- {Path(section['path']).relative_to(output_dir)} ({section['size']} bytes)\n")
            if 'strings' in section and section['strings']:
                f.write("  - **Strings**:\n")
                for s in section['strings']:
                    f.write(f"    - {s}\n")
            if 'code_sections' in section and section['code_sections']:
                f.write("  - **Code Sections**:\n")
                for cs in section['code_sections']:
                    f.write(f"    - Offset: {cs['offset']}, Size: {cs['size']} bytes\n")
                    for instr in cs['instructions']:
                        f.write(f"      - {instr}\n")
                    if cs['functions']:
                        f.write(f"      - Potential Functions: {', '.join(cs['functions'])}\n")
                    if cs['insights']:
                        f.write(f"      - Insights: {', '.join(cs['insights'])}\n")
            if 'pointers' in section and section['pointers']:
                f.write("  - **Pointers**:\n")
                for p in section['pointers']:
                    f.write(f"    - {p}\n")
        
        f.write("\n## Recommendations\n")
        for rec in result['analysis']['recommendations']:
            f.write(f"- {rec}\n")
    logger.info(f"Markdown analysis saved to {md_path}")

def print_element(element: Dict, print_type: str, csv_writer: Any, summary: bool, file_size: int) -> Dict[str, Any]:
    """Print or log element details.

    Args:
        element: Element dictionary to print.
        print_type: Output format ('normal', 'excel').
        csv_writer: CSV writer object for Excel output.
        summary: Whether to print only a summary.
        file_size: Total file size for validation.

    Returns:
        Dictionary with formatted element details.
    """
    if 'raw_data' in element:
        return {
            'offset': f"0x{element['_offset']:X}",
            'status': element.get('status', 'Corrupted'),
            'raw_data': element['raw_data']
        }
    
    emmc = decode_emmc_id(element['emmc_id'], element['emmc_id_len'])
    emi_cona = interpret_emi_cona_val(element['emi_cona_val'])
    dram_rank_size = interpret_dram_rank_size(element['dram_rank_size'])
    total_dram_size_mb = sum(size // (1024 * 1024) for size in element['dram_rank_size'])
    reserved = decode_reserved(element['reserved'])
    memory_type = 'LPDDR3' if element['type'] == 0x203 else f"Unknown (0x{element['type']:X})"
    estimated_freq = 'Unknown'  # Placeholder; can be enhanced with actual frequency calculation
    fw_id_str = decode_bytes(element['fw_id'][:element['fw_id_len']]) if element['fw_id_len'] > 0 else element['fw_id'][:element['fw_id_len']].hex().upper()
    
    recommendations = []
    if total_dram_size_mb == 0 and element['emi_cona_val'] == 0:
        recommendations.append("Element appears empty or corrupted. Verify data integrity.")
    if reserved['pointers']:
        recommendations.append("Potential pointers found in reserved field. Cross-reference with file offsets.")
    if reserved['insights']:
        recommendations.append(f"Possible structure in reserved field: {reserved['insights'][0]}")
    
    result = {
        'offset': f"0x{element['_offset']:X}",
        'memory_type': memory_type,
        'emmc': emmc,
        'firmware_id': fw_id_str,
        'emi_cona_val': element['emi_cona_val'],
        'emi_cona': emi_cona,
        'dramc_actim_val': element['dramc_actim_val'],
        'estimated_frequency': estimated_freq,
        'dram_rank_size': dram_rank_size,
        'total_dram_size_mb': total_dram_size_mb,
        'reserved': reserved,
        'reserved_non_zero': any(element['reserved']),
        'recommendations': recommendations
    }
    
    if summary:
        return result
    
    if print_type == 'excel' and csv_writer:
        csv_writer.writerow([
            memory_type,
            f"{emmc['vendor']} ({emmc['raw']})",
            fw_id_str,
            'N/A',  # NAND page size (placeholder)
            f"0x{element['emi_cona_val']:08X}",
            f"0x{element['dramc_drvctl0_val']:08X}",
            f"0x{element['dramc_drvctl1_val']:08X}",
            f"0x{element['dramc_actim_val']:08X}",
            f"0x{element['dramc_gddr3ctl1_val']:08X}",
            f"0x{element['dramc_conf1_val']:08X}",
            f"0x{element['dramc_ddr2ctl_val']:08X}",
            f"0x{element['dramc_test2_3_val']:08X}",
            f"0x{element['dramc_conf2_val']:08X}",
            f"0x{element['dramc_pd_ctrl_val']:08X}",
            f"0x{element['dramc_padctl3_val']:08X}",
            f"0x{element['dramc_dqodly_val']:08X}",
            f"0x{element['dramc_addr_output_dly']:08X}",
            f"0x{element['dramc_clk_output_dly']:08X}",
            f"0x{element['dramc_actim1_val']:08X}",
            f"0x{element['dramc_misctl0_val']:08X}",
            f"0x{element['dramc_actim05t_val']:08X}",
            memory_type,
            f"0x{element['lpddr3_mode_reg1']:08X}",
            f"0x{element['lpddr3_mode_reg2']:08X}",
            f"0x{element['lpddr3_mode_reg3']:08X}",
            f"0x{element['lpddr3_mode_reg5']:08X}",
            f"0x{element['lpddr3_mode_reg10']:08X}",
            f"0x{element['lpddr3_mode_reg63']:08X}",
            ", ".join(dram_rank_size),
            element['reserved'].hex().upper(),
            ", ".join(f"0x{x:08X}" for x in struct.unpack('<10I', element['reserved'])),
            str(emi_cona['dual_rank']),
            str(emi_cona['bus_width']),
            estimated_freq,
            ", ".join(reserved['pointers'])
        ])
    else:
        print(f"Offset: 0x{element['_offset']:X}")
        print(f"Type: {memory_type}")
        print(f"eMMC ID: {emmc['vendor']}  (Raw: {emmc['raw']}, Rev: {emmc['details'].get('revision', 'N/A')})")
        print(f"Firmware ID: {fw_id_str}")
        print(f"EMI_CONA_VAL: 0x{element['emi_cona_val']:08X} (Dual Rank: {emi_cona['dual_rank']}, Bus Width: {emi_cona['bus_width']} bits, Burst: {'Enabled' if emi_cona['burst_enabled'] else 'Disabled'})")
        print(f"DRAMC_ACTIM_VAL: 0x{element['dramc_actim_val']:08X} (Est. Freq: {estimated_freq})")
        print(f"DRAM Rank Size: {', '.join(dram_rank_size)} (Total: {total_dram_size_mb} MB)")
        print(f"Reserved: {element['reserved'].hex().upper()}")
        print(f"Reserved Analysis: {reserved['insights'][0] if reserved['insights'] else 'None'}")
        if reserved['pointers']:
            print(f"Reserved Pointers: {', '.join(reserved['pointers'])}")
        for rec in recommendations:
            print(f"Recommendations: {rec}")
    
    return result

def parse(data: bytes, print_type: str, output_dir: Path, json_output: bool = False, summary: bool = False, markdown: bool = False) -> Dict[str, Any]:
    """Parse bootloader file and extract information.

    Args:
        data: Bootloader file data.
        print_type: Output format ('normal', 'excel').
        output_dir: Directory to save extracted files.
        json_output: Whether to save JSON output.
        summary: Whether to print only a summary.
        markdown: Whether to export Markdown output.

    Returns:
        Dictionary with analysis results.
    """
    file_size = len(data)
    if file_size < Config.MIN_FILE_SIZE:
        logger.error(f"File too small to contain meaningful data ({file_size} bytes)")
        return {'file_size': file_size, 'header': {}, 'elements': [], 'additional_sections': [], 'analysis': {}}
    
    result = {
        'file_size': file_size,
        'header': {},
        'elements': [],
        'additional_sections': [],
        'analysis': {
            'emmc_vendors': set(),
            'memory_types': set(),
            'total_elements': 0,
            'valid_elements': 0,
            'empty_elements': 0,
            'corrupted_elements': 0,
            'recommendations': [],
            'patterns_found': defaultdict(list),
            'dram_size_distribution': {}
        }
    }
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Pattern search
    for name, pattern in Config.PATTERNS.items():
        if isinstance(pattern, bytes):
            pos = -1
            while True:
                pos = data.find(pattern, pos + 1)
                if pos == -1:
                    break
                result['analysis']['patterns_found'][name].append(f"0x{pos:X}")
                result['additional_sections'].append(extract_section(data, pos, len(pattern), output_dir, name, file_size=file_size))
        elif callable(pattern):
            for i in range(0, len(data) - 16, 4):
                chunk = data[i:i+4]
                if pattern(chunk, file_size):
                    result['analysis']['patterns_found'][name].append(f"0x{i:X}")
    
    # Header parsing
    header_pos = data.find(b"MTK_BLOADER_INFO")
    if header_pos == -1:
        logger.warning("MTK_BLOADER_INFO not found, proceeding with raw analysis")
        result['additional_sections'].append(analyze_remaining_data(data, 0, output_dir, file_size))
        return result
    
    if header_pos + Config.HEADER_SIZE > len(data):
        logger.error(f"Header at 0x{header_pos:X} exceeds file size")
        return result
    
    cur_pos = header_pos
    header = decode_bytes(data[cur_pos:cur_pos+27])
    cur_pos += 27
    pre_bin = decode_bytes(data[cur_pos:cur_pos+61])
    cur_pos += 61
    try:
        hex_1, hex_2, hex_3 = struct.unpack_from('<3I', data, cur_pos)
        cur_pos += 12
        mtk_bin = decode_bytes(data[cur_pos:cur_pos+8])
        cur_pos += 8
        total_custem_chips, = struct.unpack_from('<I', data, cur_pos)
        cur_pos += 4
    except struct.error as e:
        logger.error(f"Failed to parse header at 0x{header_pos:X}: {e}")
        return result
    
    result['header'] = {
        'header': header,
        'version': header.split('_v')[-1] if '_v' in header else 'Unknown',
        'pre_bin': pre_bin,
        'model': pre_bin.split('.')[0] if '.' in pre_bin else pre_bin,
        'hex_1': f"0x{hex_1:X}",
        'hex_2': f"0x{hex_2:X}",
        'hex_3': f"0x{hex_3:X}",
        'mtk_bin': mtk_bin,
        'total_custem_chips': total_custem_chips,
        '_offset': header_pos
    }
    
    if not json_output and not summary:
        print(f"Header: {header} (Version: {result['header']['version']})")
        print(f"File Name: {pre_bin}")
        print(f"Model: {result['header']['model']}")
        print(f"hex_1: 0x{hex_1:X}")
        print(f"hex_2: 0x{hex_2:X}")
        print(f"hex_3: 0x{hex_3:X}")
        print(f"mtk_bin: {mtk_bin}")
        print(f"Total Configurations: {total_custem_chips}\n")
    
    header_size = cur_pos - header_pos
    result['additional_sections'].append(extract_section(data, header_pos, header_size, output_dir, "MTK_BLOADER_INFO_HEADER", analyze=True, file_size=file_size))
    
    # CSV setup
    csv_file = None
    csv_writer = None
    if print_type == 'excel':
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_path = output_dir / f"mtk_bootloader_analysis_{timestamp}.csv"
        csv_file = csv_path.open('w', newline='', encoding='utf-8-sig')
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow([
            "Type", "eMMC ID", "Firmware ID", "NAND Page Size (B)",
            "EMI_CONA", "DRAMC_DRVCTL0", "DRAMC_DRVCTL1", "DRAMC_ACTIM",
            "DRAMC_GDDR3CTL1", "DRAMC_CONF1", "DRAMC_DDR2CTL", "DRAMC_TEST2_3",
            "DRAMC_CONF2", "DRAMC_PD_CTRL", "DRAMC_PADCTL3", "DRAMC_DQODLY",
            "DRAMC_ADDR_OUTPUT_DLY", "DRAMC_CLK_OUTPUT_DLY", "DRAMC_ACTIM1",
            "DRAMC_MISCTL0", "DRAMC_ACTIM05T", "Memory Type",
            "LPDDR3_MODE_REG1", "LPDDR3_MODE_REG2", "LPDDR3_MODE_REG3",
            "LPDDR3_MODE_REG5", "LPDDR3_MODE_REG10", "LPDDR3_MODE_REG63",
            "DRAM Rank Sizes", "Reserved (hex)", "Reserved (ints)",
            "Dual Rank", "Bus Width", "Estimated Frequency", "Reserved Pointers"
        ])
    
    result['analysis']['total_elements'] = total_custem_chips
    for i in range(total_custem_chips):
        if cur_pos + Config.ELEMENT_SIZE > len(data):
            logger.warning(f"Element {i} at 0x{cur_pos:X} exceeds file size, stopping element parsing")
            break
        if not json_output and not summary:
            print(f"--------Start Element {i}--------")
        logger.debug(f"Parsing element {i} at offset 0x{cur_pos:X}")
        start_pos = cur_pos
        cur_pos, element = read_element(data, cur_pos, file_size)
        warnings = validate_element(element, start_pos, file_size)
        for w in warnings:
            logger.warning(w)
        if element.get('status') in ('Corrupted', 'Empty or Disabled'):
            result['analysis']['corrupted_elements' if element.get('status') == 'Corrupted' else 'empty_elements'] += 1
            if not json_output and not summary and logger.getEffectiveLevel() <= logging.DEBUG:
                element_analysis = print_element(element, print_type, csv_writer, summary, file_size)
            else:
                element_analysis = {'offset': f"0x{start_pos:X}", 'status': element.get('status'), 'raw_data': element.get('raw_data', '')}
        else:
            result['analysis']['valid_elements'] += 1
            element_analysis = print_element(element, print_type, csv_writer, summary, file_size)
        result['elements'].append(element_analysis)
        
        if 'raw_data' not in element_analysis:
            total_dram_mb = element_analysis['total_dram_size_mb']
            result['analysis']['dram_size_distribution'][total_dram_mb] = result['analysis']['dram_size_distribution'].get(total_dram_mb, 0) + 1
            result['analysis']['emmc_vendors'].add(element_analysis['emmc']['vendor'])
            result['analysis']['memory_types'].add(element_analysis['memory_type'])
        if not json_output and not summary:
            print(f"--------End Element {i}--------\n")
        result['additional_sections'].append(extract_section(data, start_pos, cur_pos - start_pos, output_dir, f"ELEMENT_{i}", analyze=True, file_size=file_size))
    
    if cur_pos + 4 <= len(data):
        try:
            size, = struct.unpack_from('<I', data, cur_pos)
            result['size'] = size
            if not json_output and not summary:
                print(f"Size: {size}")
            result['additional_sections'].append(extract_section(data, cur_pos, 4, output_dir, "SIZE_FIELD", analyze=False, file_size=file_size))
            cur_pos += 4
        except struct.error as e:
            logger.error(f"Failed to parse size field at 0x{cur_pos:X}: {e}")
    
    if cur_pos < len(data):
        remaining_size = len(data) - cur_pos
        remaining_data = data[cur_pos:]
        result['additional_sections'].append(extract_section(data, cur_pos, remaining_size, output_dir, "REMAINING_DATA", analyze=False, file_size=file_size))
        remaining_analysis = analyze_remaining_data(remaining_data, cur_pos, output_dir, file_size)
        result['additional_sections'].append(remaining_analysis)
        if remaining_analysis['strings'] or remaining_analysis['code_sections'] or remaining_analysis['pointers']:
            result['analysis']['recommendations'].append("Found strings, code, or pointers in REMAINING_DATA. Review for additional firmware insights.")
    
    if csv_file:
        csv_file.close()
        logger.info(f"CSV output saved to {csv_path}")
    
    generate_flash_tool_config([e for e in result['elements'] if e.get('status') not in ('Corrupted', 'Empty or Disabled')], output_dir)
    
    if len(result['analysis']['emmc_vendors']) > 1:
        result['analysis']['recommendations'].append(
            f"Supports {len(result['analysis']['emmc_vendors'])} eMMC vendors: {', '.join(result['analysis']['emmc_vendors'])}. Verify storage compatibility."
        )
    if any(e.get('reserved_non_zero', False) for e in result['elements'] if e.get('status') not in ('Corrupted', 'Empty or Disabled')):
        result['analysis']['recommendations'].append(
            "Non-zero data in reserved fields. Analyze extracted files for potential firmware data."
        )
    if result['analysis']['corrupted_elements'] > 0:
        result['analysis']['recommendations'].append(
            f"{result['analysis']['corrupted_elements']} corrupted elements detected. File may be damaged or use an alternate structure."
        )
    if result['analysis']['empty_elements'] > 0:
        result['analysis']['recommendations'].append(
            f"{result['analysis']['empty_elements']} empty or disabled elements detected. May indicate unused configurations."
        )
    
    if not json_output and not summary:
        print("\nAnalysis Summary:")
        print(f"Supported eMMC Vendors: {', '.join(result['analysis']['emmc_vendors'])}")
        print(f"Memory Types: {', '.join(result['analysis']['memory_types'])}")
        print(f"Total Elements: {result['analysis']['total_elements']}")
        print(f"Valid Elements: {result['analysis']['valid_elements']}")
        print(f"Empty or Disabled Elements: {result['analysis']['empty_elements']}")
        print(f"Corrupted Elements: {result['analysis']['corrupted_elements']}")
        print(f"DRAM Size Distribution:")
        for size, count in sorted(result['analysis']['dram_size_distribution'].items()):
            unit = "MB" if size < 1024 else "GB"
            display_size = size if unit == "MB" else size // 1024
            print(f"  {display_size} {unit}: {'*' * count} ({count} elements)")
        for section in result['additional_sections']:
            if 'path' in section and section['path']:
                print(f"Extracted Section: {Path(section['path']).relative_to(output_dir)} ({section['size']} bytes)")
            if 'strings' in section and section['strings']:
                print("Strings Found:")
                for s in section['strings']:
                    print(f"  {s}")
            if 'code_sections' in section and section['code_sections']:
                print("Code Sections Found:")
                for cs in section['code_sections']:
                    print(f"  Offset: {cs['offset']}, Size: {cs['size']} bytes")
                    for instr in cs['instructions']:
                        print(f"    {instr}")
                    if cs['functions']:
                        print(f"    Potential Functions: {', '.join(cs['functions'])}")
                    if cs['insights']:
                        print(f"    Insights: {', '.join(cs['insights'])}")
            if 'pointers' in section and section['pointers']:
                print("Pointers Found:")
                for p in section['pointers']:
                    print(f"  {p}")
        for rec in result['analysis']['recommendations']:
            print(f"Recommendation: {rec}")
    
    if json_output:
        json_path = output_dir / "analysis.json"
        result_json = result.copy()
        result_json['analysis']['emmc_vendors'] = list(result['analysis']['emmc_vendors'])
        result_json['analysis']['memory_types'] = list(result['analysis']['memory_types'])
        with json_path.open('w', encoding='utf-8') as f:
            json.dump(result_json, f, indent=2)
        logger.info(f"JSON analysis saved to {json_path}")
    
    if markdown:
        export_markdown(result, output_dir)
    
    return result

def main():
    """Main function to parse arguments and run the analysis."""
    parser = argparse.ArgumentParser(
        description=(
            "Advanced MediaTek bootloader info extractor.\n"
            "Extracts detailed information about eMMC, DRAM, firmware, and other sections from MediaTek bootloader files.\n"
            "Supports CSV, JSON, and Markdown output formats for analysis.\n"
            "Example: python mtk_bootloader_analysis.py --excel --json --markdown preloader.bin"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '-e', '--excel',
        action='store_const',
        const='excel',
        dest='print_type',
        default='normal',
        help="Output in tab-separated CSV format"
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path.cwd() / 'output',
        help="Directory to save extracted files and outputs (default: ./output)"
    )
    parser.add_argument(
        '--log-dir',
        type=Path,
        default=Path.home() / '.mtk_bootloader_analysis' / 'logs',
        help="Directory to save log files (default: ~/.mtk_bootloader_analysis/logs)"
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help="Save analysis in JSON format"
    )
    parser.add_argument(
        '--summary',
        action='store_true',
        help="Display a concise summary only"
    )
    parser.add_argument(
        '--markdown',
        action='store_true',
        help="Export analysis as a Markdown file"
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help="Enable detailed logging"
    )
    parser.add_argument(
        'filename',
        type=Path,
        help="Path to bootloader file (e.g., ./preloader.bin)"
    )
    args = parser.parse_args()

    global LOG_DIR
    LOG_DIR = args.log_dir
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    LOG_FILE = LOG_DIR / f"mtk_bootloader_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(LOG_FILE, encoding='utf-8')
        ]
    )

    if not args.filename.is_file():
        logger.error(f"File not found: {args.filename}")
        sys.exit(1)
    
    file_size = args.filename.stat().st_size
    if file_size < Config.MIN_FILE_SIZE:
        logger.error(f"File too small to contain meaningful data: {args.filename} ({file_size} bytes)")
        sys.exit(1)

    logger.info(f"Processing bootloader \"{args.filename}\" ({file_size} bytes)")
    try:
        with args.filename.open('rb') as f:
            data = f.read()
    except IOError as e:
        logger.error(f"Failed to read file {args.filename}: {e}")
        sys.exit(1)

    parse(data, args.print_type, args.output_dir, args.json, args.summary, args.markdown)

if __name__ == "__main__":
    main()
