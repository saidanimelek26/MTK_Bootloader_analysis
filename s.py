#!/usr/bin/env python3
import argparse
import csv
import json
import logging
import os
import struct
import sys
from datetime import datetime
from pathlib import Path
from typing import Tuple, Dict, List, Optional, Any
from collections import defaultdict

# Attempt to import Capstone for disassembly
try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    print("Warning: Capstone not installed. Disassembly unavailable. Install with: pip install capstone")

# Setup logging
log_dir = Path(os.getenv('LOCALAPPDATA', Path.home() / 'AppData' / 'Local')) / 'MTK_Bootloader_Analysis' / 'logs'
log_dir.mkdir(parents=True, exist_ok=True)
log_file = log_dir / f"MTK_Bootloader_Analysis_info_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file, encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# eMMC vendor dictionary
EMMC_VENDORS = {
    b'\x15\x01\x00': 'Samsung',
    b'\x70\x01\x00': 'SK Hynix',
    b'\x90\x01\x4A': 'Hynix',
    b'\x45\x01\x00': 'Sandisk',
    b'\xFE\x01\x4A': 'Micron',
}

# Known patterns to search for
PATTERNS = {
    'MTK_BLOADER_INFO': b'MTK_BLOADER_INFO',  # Keep original identifier for file parsing
    'MTK_BIN': b'MTK_BIN',
    'ARM_CODE_NOP': b'\x00\xF0\x20\xE3',  # ARM NOP
    'STRING': lambda x: len(x) > 4 and all(32 <= c < 127 for c in x),
    'POTENTIAL_PTR': lambda x: len(x) == 4 and 0x1000 <= int.from_bytes(x, 'little') <= 0x1FFFFF,
}

def decode_bytes(data: bytes) -> str:
    """Decode bytes to ASCII string or return hex if not printable."""
    try:
        ascii_str = data.split(b'\x00')[0].decode('ascii', errors='ignore').strip()
        if ascii_str and all(c.isprintable() for c in ascii_str):
            return ascii_str
        return data.hex().upper()
    except UnicodeDecodeError:
        return data.hex().upper()

def decode_emmc_id(emmc_id: bytes, emmc_id_len: int) -> Dict[str, Any]:
    """Decode eMMC ID with manufacturer info and additional details."""
    if not 0 <= emmc_id_len <= 16:
        return {'vendor': 'Not Available', 'model': '', 'raw': emmc_id.hex().upper(), 'details': {'error': f'Invalid length: {emmc_id_len}'}}
    
    vendor_prefix = emmc_id[:3]
    vendor = EMMC_VENDORS.get(vendor_prefix, 'Unknown')
    model_bytes = emmc_id[3:emmc_id_len]
    model_str = model_bytes.decode('ascii', errors='ignore').strip()
    model = model_str if all(c.isprintable() for c in model_str) else model_bytes.hex().upper()
    
    details = {}
    if vendor != 'Unknown' and len(model_bytes) >= 2:
        details['revision'] = model_bytes[-2:].hex().upper()
        details['capacity_hint'] = 'Unknown'
    
    return {
        'vendor': vendor,
        'model': model,
        'raw': emmc_id[:max(emmc_id_len, 16)].hex().upper(),
        'details': details
    }

def interpret_dram_rank_size(rank_sizes: Tuple[int, ...]) -> List[str]:
    """Interpret DRAM rank sizes into logical units."""
    sizes = []
    for size in rank_sizes:
        if size == 0:
            sizes.append("0 MB")
        else:
            mb = size // (1024 * 1024)
            sizes.append(f"{mb // 1024} GB" if mb >= 1024 else f"{mb} MB")
    return sizes

def decode_dram_settings(element: Dict) -> Dict[str, Any]:
    """Decode DRAM settings with detailed timing and configuration analysis."""
    emi_cona = element['emi_cona_val']
    actim = element['dramc_actim_val']
    
    emi_settings = {
        'dual_rank': bool(emi_cona & (1 << 17)),
        'bus_width': 16 if emi_cona & (1 << 2) else 32,
        'burst_mode': 'Enabled' if emi_cona & (1 << 0) else 'Disabled',
        'raw_value': f"0x{emi_cona:08X}"
    }
    
    actim_settings = {
        'raw_value': f"0x{actim:08X}",
        'possible_frequency': 'Unknown'
    }
    trfc = (actim >> 24) & 0xFF
    if 0x10 <= trfc <= 0x50:
        freq_est = round(1600 / (trfc / 16), 1)
        actim_settings['possible_frequency'] = f"~{freq_est} MHz"
    
    return {
        'emi_cona': emi_settings,
        'actim': actim_settings,
        'additional_regs': {
            'drvctl0': f"0x{element['dramc_drvctl0_val']:08X}",
            'drvctl1': f"0x{element['dramc_drvctl1_val']:08X}",
            'conf1': f"0x{element['dramc_conf1_val']:08X}"
        }
    }

def decode_reserved(reserved: bytes, file_size: int) -> Dict[str, Any]:
    """Decode reserved field with advanced analysis and size checking."""
    decoded = {
        'hex': reserved.hex().upper(),
        'ints': [],
        'text': reserved.decode('ascii', errors='ignore').strip(),
        'potential_pointers': [],
        'potential_structures': [],
        'entropy': sum(reserved.count(b) for b in set(reserved)) / len(reserved) if reserved else 0
    }
    
    if len(reserved) < 40:
        logger.warning(f"Reserved field shorter than expected ({len(reserved)} bytes), padding with zeros")
        reserved_padded = reserved + b'\x00' * (40 - len(reserved))
    else:
        reserved_padded = reserved[:40]
    
    try:
        decoded['ints'] = list(struct.unpack('<10I', reserved_padded))
    except struct.error as e:
        logger.error(f"Failed to unpack reserved field: {e}")
        decoded['ints'] = []
    
    for i in range(0, len(reserved_padded) - 3, 4):
        val = struct.unpack_from('<I', reserved_padded, i)[0]
        if 0x1000 <= val < file_size:
            decoded['potential_pointers'].append(f"0x{val:08X} at offset {i}")
    
    unique_bytes = len(set(reserved))
    if unique_bytes > 10 and decoded['entropy'] > 0.9:
        decoded['potential_structures'].append("High entropy: Possible encrypted data")
    elif unique_bytes < 5 and any(reserved):
        decoded['potential_structures'].append("Low variety: Possible repeating pattern or table")
    
    decoded['interpreted'] = (
        'Possible string or identifier' if decoded['text'] and len(decoded['text']) > 4 else
        'Possible memory pointers' if decoded['potential_pointers'] else
        'Possible data structure or encrypted' if decoded['potential_structures'] else
        'No clear interpretation'
    )
    
    return decoded

def disassemble_code(data: bytes, offset: int) -> Dict[str, Any]:
    """Enhanced ARM disassembly with function detection and insights."""
    if not CAPSTONE_AVAILABLE:
        return {'instructions': ["Disassembly unavailable (install capstone)"], 'functions': [], 'insights': []}
    
    try:
        modes = [(CS_MODE_ARM, "ARM"), (CS_MODE_THUMB, "Thumb")]
        result = {'instructions': [], 'functions': [], 'insights': []}
        
        for mode, mode_name in modes:
            md = Cs(CS_ARCH_ARM, mode)
            instructions = []
            func_starts = []
            branch_targets = set()
            
            for i, (address, size, mnemonic, op_str) in enumerate(md.disasm_lite(data, offset)):
                if i >= 30:
                    instructions.append("... (more instructions available)")
                    break
                instr = f"0x{address:08X}: {mnemonic} {op_str}"
                instructions.append(instr)
                
                if i == 0 and mnemonic in ('push', 'stmfd', 'sub sp'):
                    func_starts.append(f"0x{address:08X} ({mode_name})")
                
                if mnemonic.startswith('b') and op_str.startswith('0x'):
                    try:
                        target = int(op_str, 16)
                        branch_targets.add(target)
                    except ValueError:
                        pass
            
            if instructions:
                result['instructions'] = instructions
                result['functions'] = func_starts
                if branch_targets:
                    result['functions'].extend(f"0x{t:08X} ({mode_name})" for t in branch_targets if t >= offset)
                    result['insights'].append(f"Branch targets detected: {', '.join(f'0x{t:08X}' for t in branch_targets)}")
                if func_starts:
                    result['insights'].append(f"Potential function entry in {mode_name} mode at {func_starts[0]}")
                break
        
        if not result['instructions']:
            result['instructions'] = ["No valid instructions found"]
        elif len(result['instructions']) > 10:
            result['insights'].append("Significant code section detected. Review for bootloader logic.")
        
        return result
    except Exception as e:
        return {'instructions': [f"Disassembly error: {e}"], 'functions': [], 'insights': []}

def extract_section(data: bytes, start: int, size: int, output_dir: Path, name: str, analyze: bool = False, file_size: int = 0) -> Dict[str, Any]:
    """Extract a data section to a file with optional analysis."""
    section = data[start:start + size]
    output_path = output_dir / f"{name}_{start:08X}_{size}.bin"
    with output_path.open('wb') as f:
        f.write(section)
    logger.info(f"Extracted section '{name}' at 0x{start:X} (size: {size} bytes) to {output_path}")
    
    analysis = {'path': str(output_path), 'size': size}
    if analyze and size > 4:
        analysis['strings'] = [s for s in section.decode('ascii', errors='ignore').split('\x00') if len(s) > 4 and all(c.isprintable() for c in s)]
        disasm = disassemble_code(section, start)
        analysis.update(disasm)
        if name.startswith('ELEMENT'):
            analysis['reserved'] = {}
        else:
            analysis['reserved'] = {}
    return analysis

def validate_element(element: Dict, offset: int) -> List[str]:
    """Validate element data with improved context."""
    warnings = []
    if not 0 <= element['emmc_id_len'] <= 16:
        warnings.append(f"Invalid eMMC ID length at offset 0x{offset:X}: {element['emmc_id_len']} (expected 0-16)")
    if not 0 <= element['fw_id_len'] <= 8:
        warnings.append(f"Invalid firmware ID length at offset 0x{offset:X}: {element['fw_id_len']} (expected 0-8)")
    total_mb = sum(size // (1024 * 1024) for size in element['dram_rank_size'])
    if total_mb > 16384:
        warnings.append(f"Unrealistic total DRAM size at offset 0x{offset:X}: {total_mb} MB")
    if element['type'] not in (0x203, 0) and not (0x100 <= element['type'] <= 0xFFFF):
        warnings.append(f"Unusual memory type at offset 0x{offset:X}: 0x{element['type']:X}")
    return warnings

def read_element(data: bytes, offset: int, file_size: int) -> Tuple[int, Dict]:
    """Read a single element with corruption detection."""
    try:
        if offset + 188 > len(data):
            raise ValueError("Insufficient data for complete element")
        
        cur_pos = offset
        element = {'_offset': offset}
        fields = struct.unpack_from('<4I', data, cur_pos)
        element['sub_version'], element['type'], element['emmc_id_len'], element['fw_id_len'] = fields
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
        element['dramc_actim05t_val'] = dram_fields[:17]
        cur_pos += 68
        element['dram_rank_size'] = struct.unpack_from('<4I', data, cur_pos)
        cur_pos += 16
        element['reserved'] = data[cur_pos:cur_pos+40]
        cur_pos += 40
        lpddr3_regs = struct.unpack_from('<6I', data, cur_pos)
        element['lpddr3_mode_reg1'], element['lpddr3_mode_reg2'], element['lpddr3_mode_reg3'], \
        element['lpddr3_mode_reg5'], element['lpddr3_mode_reg10'], element['lpddr3_mode_reg63'] = lpddr3_regs
        cur_pos += 24
        
        if all(v == 0 for v in element['dram_rank_size']) and element['emi_cona_val'] == 0 and element['dramc_actim_val'] == 0:
            logger.warning(f"Possible corrupted or empty element at offset 0x{offset:X}")
        
        return cur_pos, element
    except (struct.error, ValueError) as e:
        logger.error(f"Failed to parse element at offset 0x{offset:X}: {e}")
        element = {'_offset': offset, 'raw_data': data[offset:min(offset + 188, len(data))].hex().upper()}
        return offset + 188, element

def print_element(element: Dict, print_type: str, csv_writer: Optional[csv.writer] = None, summary: bool = False, file_size: int = 0) -> Dict[str, Any]:
    """Print or save element data with enhanced analysis."""
    if 'raw_data' in element:
        analysis = {
            'offset': f"0x{element['_offset']:X}",
            'status': 'Corrupted or unparsed',
            'raw_data': element['raw_data'],
            'recommendations': ["Investigate raw data for alternate structure"]
        }
        if not summary:
            print(f"Offset: {analysis['offset']}")
            print(f"Status: {analysis['status']}")
            print(f"Raw Data: {analysis['raw_data']}")
            print(f"Recommendations: {', '.join(analysis['recommendations'])}")
        return analysis
    
    emmc_info = decode_emmc_id(element['emmc_id'], element['emmc_id_len'])
    fw_id_str = decode_bytes(element['fw_id'][:min(element['fw_id_len'], 8)]) if element['fw_id_len'] > 0 else f"Raw: {element['fw_id'].hex().upper()}"
    dram_rank_sizes = interpret_dram_rank_size(element['dram_rank_size'])
    reserved_info = decode_reserved(element['reserved'], file_size)
    dram_settings = decode_dram_settings(element)
    
    total_dram_mb = sum(int(s.split()[0]) * (1024 if 'GB' in s else 1) for s in dram_rank_sizes)
    
    analysis = {
        'offset': f"0x{element['_offset']:X}",
        'emmc': emmc_info,
        'fw_id': fw_id_str,
        'dram_rank_sizes': dram_rank_sizes,
        'total_dram_size_mb': total_dram_mb,
        'dram_settings': dram_settings,
        'memory_type': 'LPDDR3' if element['type'] == 0x203 else f"Unknown (0x{element['type']:X})",
        'reserved_non_zero': any(element['reserved']),
        'reserved_info': reserved_info,
        'recommendations': []
    }
    
    if total_dram_mb > 16384:
        analysis['recommendations'].append("Unrealistic DRAM size detected. Verify units or corruption.")
    if reserved_info['potential_pointers']:
        analysis['recommendations'].append("Potential pointers found in reserved field. Cross-reference with file offsets.")
    if reserved_info['potential_structures']:
        analysis['recommendations'].append(f"Possible structure in reserved field: {reserved_info['potential_structures'][0]}")
    if total_dram_mb == 0 and any(element['dram_rank_size']) == 0 and element['emi_cona_val'] == 0:
        analysis['recommendations'].append("Element appears empty or corrupted. Verify data integrity.")
    
    if summary:
        print(f"Element at offset {analysis['offset']}:")
        print(f"  eMMC: {emmc_info['vendor']} {emmc_info['model']} (Rev: {emmc_info['details'].get('revision', 'N/A')})")
        print(f"  DRAM: {', '.join(dram_rank_sizes)} (Total: {total_dram_mb} MB)")
        print(f"  Type: {analysis['memory_type']}")
        print(f"  DRAM Settings: Dual Rank={dram_settings['emi_cona']['dual_rank']}, Bus Width={dram_settings['emi_cona']['bus_width']} bits, Freq={dram_settings['actim']['possible_frequency']}")
        return analysis
    
    if print_type == 'excel':
        row = [
            analysis['memory_type'],
            f"{emmc_info['vendor']} {emmc_info['model']}",
            fw_id_str,
            "",
            dram_settings['emi_cona']['raw_value'],
            dram_settings['additional_regs']['drvctl0'],
            dram_settings['additional_regs']['drvctl1'],
            dram_settings['actim']['raw_value'],
            f"0x{element['dramc_gddr3ctl1_val']:08X}",
            dram_settings['additional_regs']['conf1'],
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
            analysis['memory_type'],
            f"0x{element['lpddr3_mode_reg1']:08X}",
            f"0x{element['lpddr3_mode_reg2']:08X}",
            f"0x{element['lpddr3_mode_reg3']:08X}",
            f"0x{element['lpddr3_mode_reg5']:08X}",
            f"0x{element['lpddr3_mode_reg10']:08X}",
            f"0x{element['lpddr3_mode_reg63']:08X}",
            ", ".join(dram_rank_sizes),
            reserved_info['hex'],
            ", ".join(f"0x{x:08X}" for x in reserved_info['ints']) if reserved_info['ints'] else "",
            str(dram_settings['emi_cona']['dual_rank']),
            str(dram_settings['emi_cona']['bus_width']),
            dram_settings['actim']['possible_frequency'],
            ", ".join(reserved_info['potential_pointers']) if reserved_info['potential_pointers'] else "None"
        ]
        if csv_writer:
            csv_writer.writerow(row)
        return analysis
    
    lines = [
        f"Offset: {analysis['offset']}",
        f"Type: {analysis['memory_type']}",
        f"eMMC ID: {emmc_info['vendor']} {emmc_info['model']} (Raw: {emmc_info['raw']}, Rev: {emmc_info['details'].get('revision', 'N/A')})",
        f"Firmware ID: {fw_id_str}",
        f"EMI_CONA_VAL: {dram_settings['emi_cona']['raw_value']} (Dual Rank: {dram_settings['emi_cona']['dual_rank']}, Bus Width: {dram_settings['emi_cona']['bus_width']} bits, Burst: {dram_settings['emi_cona']['burst_mode']})",
        f"DRAMC_ACTIM_VAL: {dram_settings['actim']['raw_value']} (Est. Freq: {dram_settings['actim']['possible_frequency']})",
        f"DRAM Rank Size: {', '.join(dram_rank_sizes)} (Total: {total_dram_mb} MB)",
        f"Reserved: {reserved_info['hex']}",
        f"Reserved Analysis: {reserved_info['interpreted']}",
        f"Reserved Pointers: {', '.join(reserved_info['potential_pointers']) if reserved_info['potential_pointers'] else 'None'}",
        f"Recommendations: {', '.join(analysis['recommendations']) if analysis['recommendations'] else 'None'}"
    ]
    for line in lines:
        print(line)
    return analysis

def generate_flash_tool_config(elements: List[Dict], output_dir: Path) -> None:
    """Generate an enhanced SP Flash Tool memory config file."""
    config = [
        "# SP Flash Tool Memory Configuration",
        "# Generated by MTK_Bootloader_Analysis",
        ""
    ]
    for i, element in enumerate(elements):
        if 'raw_data' in element:
            config.append(f"# Element {i} at offset {element['offset']} (Corrupted)")
            config.append(f"RAW_DATA: {element['raw_data']}")
            continue
        config.append(f"# Element {i} at offset {element['offset']}")
        config.append(f"EMMC_ID: {element['emmc']['raw']}")
        config.append(f"DRAM_TYPE: {element['memory_type']}")
        config.append(f"DRAM_RANK_SIZE: {', '.join(element['dram_rank_sizes'])}")
        config.append(f"EMI_CONA_VAL: {element['dram_settings']['emi_cona']['raw_value']}")
        config.append(f"ACTIM_VAL: {element['dram_settings']['actim']['raw_value']} (Freq: {element['dram_settings']['actim']['possible_frequency']})")
        config.append("")
    
    config_path = output_dir / "flash_tool_memory_config.txt"
    with config_path.open('w', encoding='utf-8') as f:
        f.write("\n".join(config))
    logger.info(f"Generated SP Flash Tool config at {config_path}")

def analyze_remaining_data(data: bytes, start: int, output_dir: Path, file_size: int) -> Dict[str, Any]:
    """Enhanced analysis of remaining data."""
    analysis = {
        'offset': f"0x{start:X}",
        'size': len(data),
        'strings': [],
        'code_sections': [],
        'pointers': [],
        'insights': [],
        'entropy': sum(data.count(b) for b in set(data)) / len(data) if data else 0
    }
    
    current_str = ""
    for i in range(len(data)):
        char = data[i]
        if 32 <= char < 127:
            current_str += chr(char)
        elif current_str:
            if len(current_str) > 4:
                analysis['strings'].append(f"0x{start + i - len(current_str):X}: {current_str}")
            current_str = ""
    
    for i in range(0, len(data) - 3, 4):
        val = struct.unpack_from('<I', data, i)[0]
        if 0x1000 <= val < file_size:
            analysis['pointers'].append(f"0x{start + i:X}: 0x{val:08X}")
    
    if CAPSTONE_AVAILABLE:
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        code_start = None
        instructions = []
        for i in range(0, len(data) - 3, 4):
            chunk = data[i:i+4]
            disasm_result = list(md.disasm(chunk, start + i))
            if disasm_result:
                if code_start is None:
                    code_start = start + i
                instructions.extend(f"0x{a:08X}: {m} {o}" for a, s, m, o in md.disasm_lite(chunk, start + i))
            elif code_start is not None and instructions:
                section_size = i - (code_start - start)
                disasm_analysis = disassemble_code(data[code_start - start:code_start - start + section_size], code_start)
                analysis['code_sections'].append({
                    'offset': f"0x{code_start:X}",
                    'size': section_size,
                    'instructions': disasm_analysis['instructions'][:10],
                    'functions': disasm_analysis['functions'],
                    'insights': disasm_analysis['insights']
                })
                extract_section(data[code_start - start:i], code_start, section_size, output_dir, "CODE_SECTION", analyze=False, file_size=file_size)
                code_start = None
                instructions = []
        
        if instructions and code_start is not None:
            section_size = len(data) - (code_start - start)
            disasm_analysis = disassemble_code(data[code_start - start:], code_start)
            analysis['code_sections'].append({
                'offset': f"0x{code_start:X}",
                'size': section_size,
                'instructions': disasm_analysis['instructions'][:10],
                'functions': disasm_analysis['functions'],
                'insights': disasm_analysis['insights']
            })
            extract_section(data[code_start - start:], code_start, section_size, output_dir, "CODE_SECTION", analyze=False, file_size=file_size)
    
    if analysis['entropy'] > 0.9:
        analysis['insights'].append("High entropy detected: Possible encrypted or compressed section")
    if analysis['pointers']:
        analysis['insights'].append(f"Pointers found: May reference offsets within file (size: {file_size} bytes)")
    if analysis['code_sections']:
        analysis['insights'].append("Executable code detected: Potential bootloader logic or initialization routines")
    
    return analysis

def export_markdown(result: Dict, output_dir: Path) -> None:
    """Export detailed analysis to Markdown."""
    md_lines = [
        "# MTK Bootloader Analysis",
        f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**File Size**: {result.get('file_size', 'Unknown')} bytes",
        "",
        "## Header",
        f"- **Name**: {result['header']['header']}",
        f"- **Version**: {result['header']['version']}",
        f"- **File**: {result['header']['pre_bin']}",
        f"- **Model**: {result['header']['model']}",
        "",
        "## Elements",
    ]
    for i, elem in enumerate(result['elements']):
        md_lines.append(f"### Element {i} ({elem['offset']})")
        if 'raw_data' in elem:
            md_lines.append(f"- **Status**: {elem['status']}")
            md_lines.append(f"- **Raw Data**: `{elem['raw_data']}`")
        else:
            md_lines.append(f"- **eMMC**: {elem['emmc']['vendor']} {elem['emmc']['model']} ({elem['emmc']['raw']})")
            md_lines.append(f"- **DRAM**: {', '.join(elem['dram_rank_sizes'])} (Total: {elem['total_dram_size_mb']} MB)")
            md_lines.append(f"- **Type**: {elem['memory_type']}")
            md_lines.append(f"- **Frequency**: {elem['dram_settings']['actim']['possible_frequency']}")
            md_lines.append(f"- **Reserved**: `{elem['reserved_info']['hex']}`")
            md_lines.append(f"- **Reserved Analysis**: {elem['reserved_info']['interpreted']}")
        md_lines.append("")
    
    md_lines.append("## Remaining Data")
    for section in result['additional_sections']:
        if 'code_sections' in section:
            for cs in section['code_sections']:
                md_lines.append(f"- **Code Section at {cs['offset']}** (Size: {cs['size']} bytes)")
                md_lines.append("  ```")
                md_lines.extend(f"  {instr}" for instr in cs['instructions'])
                md_lines.append("  ```")
                if cs['functions']:
                    md_lines.append(f"  - **Functions**: {', '.join(cs['functions'])}")
    
    md_lines.append("## Recommendations")
    for rec in result['analysis']['recommendations']:
        md_lines.append(f"- {rec}")
    
    md_path = output_dir / "analysis_report.md"
    with md_path.open('w', encoding='utf-8') as f:
        f.write("\n".join(md_lines))
    logger.info(f"Exported Markdown report to {md_path}")

def parse(data: bytes, print_type: str, output_dir: Path, json_output: bool = False, summary: bool = False, markdown: bool = False) -> Dict[str, Any]:
    """Parse the entire preloader file with maximum extraction."""
    file_size = len(data)
    result = {
        'file_size': file_size,
        'header': {},
        'elements': [],
        'additional_sections': [],
        'analysis': {
            'emmc_vendors': set(),
            'memory_types': set(),
            'total_elements': 0,
            'recommendations': [],
            'patterns_found': defaultdict(list),
            'dram_size_distribution': {}
        }
    }
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    for name, pattern in PATTERNS.items():
        if isinstance(pattern, bytes):
            pos = -1
            while True:
                pos = data.find(pattern, pos + 1)
                if pos == -1:
                    break
                result['analysis']['patterns_found'][name].append(f"0x{pos:X}")
                extract_section(data, pos, len(pattern), output_dir, name, file_size=file_size)
        elif callable(pattern):
            for i in range(0, len(data) - 16, 4):
                chunk = data[i:i+16]
                if pattern(chunk):
                    result['analysis']['patterns_found'][name].append(f"0x{i:X}")
    
    header_pos = data.find(b"MTK_BLOADER_INFO")
    if header_pos == -1:
        logger.warning("MTK_BLOADER_INFO not found, proceeding with raw analysis")
        result['additional_sections'].append(analyze_remaining_data(data, 0, output_dir, file_size))
        return result
    
    cur_pos = header_pos
    header = decode_bytes(data[cur_pos:cur_pos+27])
    cur_pos += 27
    pre_bin = decode_bytes(data[cur_pos:cur_pos+61])
    cur_pos += 61
    hex_1, hex_2, hex_3 = struct.unpack_from('<3I', data, cur_pos)
    cur_pos += 12
    mtk_bin = decode_bytes(data[cur_pos:cur_pos+8])
    cur_pos += 8
    total_custem_chips, = struct.unpack_from('<I', data, cur_pos)
    cur_pos += 4
    
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
    
    csv_file = None
    csv_writer = None
    if print_type == 'excel':
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_path = output_dir / f"MTK_Bootloader_Analysis_info_{timestamp}.csv"
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
        if not json_output and not summary:
            print(f"--------Start Element {i}--------")
        logger.debug(f"Parsing element {i} at offset 0x{cur_pos:X}")
        start_pos = cur_pos
        cur_pos, element = read_element(data, cur_pos, file_size)
        warnings = validate_element(element, start_pos)
        for w in warnings:
            logger.warning(w)
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
        size, = struct.unpack_from('<I', data, cur_pos)
        result['size'] = size
        if not json_output and not summary:
            print(f"Size: {size}")
        result['additional_sections'].append(extract_section(data, cur_pos, 4, output_dir, "SIZE_FIELD", analyze=False, file_size=file_size))
        cur_pos += 4
    
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
    
    generate_flash_tool_config(result['elements'], output_dir)
    
    if len(result['analysis']['emmc_vendors']) > 1:
        result['analysis']['recommendations'].append(
            f"Supports {len(result['analysis']['emmc_vendors'])} eMMC vendors: {', '.join(result['analysis']['emmc_vendors'])}. Verify storage compatibility."
        )
    if any(e.get('reserved_non_zero', False) for e in result['elements']):
        result['analysis']['recommendations'].append(
            "Non-zero data in reserved fields. Analyze extracted files for potential firmware data."
        )
    if any('Corrupted' in e.get('status', '') for e in result['elements']):
        result['analysis']['recommendations'].append(
            "Corrupted elements detected. File may be damaged or use an alternate structure."
        )
    
    if not json_output and not summary:
        print("\nAnalysis Summary:")
        print(f"Supported eMMC Vendors: {', '.join(result['analysis']['emmc_vendors'])}")
        print(f"Memory Types: {', '.join(result['analysis']['memory_types'])}")
        print(f"Total Elements: {result['analysis']['total_elements']}")
        print(f"DRAM Size Distribution:")
        for size, count in result['analysis']['dram_size_distribution'].items():
            print(f"  {size} MB: {'*' * count} ({count} elements)")
        for section in result['additional_sections']:
            if 'path' in section:
                print(f"Extracted Section: {section['path']} ({section['size']} bytes)")
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
    parser = argparse.ArgumentParser(
        description=(
            "Advanced MediaTek bootloader info extractor.\n"
            "Extracts all possible data with deep analysis for reverse engineering and firmware development."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '-e', '--excel',
        action='store_const',
        const='excel',
        dest='print_type',
        default='normal',
        help="Output in tab-separated format (enables CSV export)"
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path.cwd() / 'output',
        help="Directory to save extracted files and outputs (default: ./output)"
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
        help="Path to bootloader file (e.g., C:\\path\\to\\preloader.bin)"
    )
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if not args.filename.is_file():
        logger.error(f"File not found: {args.filename}")
        sys.exit(1)
    file_size = args.filename.stat().st_size
    if file_size < 128:
        logger.error(f"File too small to contain meaningful data: {args.filename}")
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