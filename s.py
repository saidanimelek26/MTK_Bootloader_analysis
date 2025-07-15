import argparse
import logging
import re
import struct
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
import json
import markdown
try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

class Config:
    SECTION_PATTERNS = {
        'MTK_BLOADER_INFO': re.compile(b'MTK_BLOADER_INFO_v[0-9]{2}'),
        'MTK_BLOADER_INFO_HEADER': re.compile(b'MTK_BLOADER_INFO_v[0-9]{2}'),
        'MTK_BIN': re.compile(b'MTK_BIN'),
        'ARM_CODE_NOP': re.compile(b'\x00\xF0\x20\xE3|\x00\x00\xA0\xE1')
    }
    EMMC_VENDORS = {
        b'\x15\x01\x00': 'Samsung',
        b'\x90\x01\x4A': 'Hynix',
        b'\x45\x01\x00': 'Sandisk',
        b'\x70\x01\x00': 'Kingston',
        b'\x03\x00\x44': 'Unknown Vendor (0x030044)'
    }
    MAX_EMMC_ID_LEN = 16
    MAX_FW_ID_LEN = 8
    MAX_CODE_SECTION_SIZE = 4096
    POTENTIAL_PTR = lambda x, file_size: (
        len(x) == 4 and
        (val := struct.unpack('<I', x)[0]) > 0x1000 and
        val < file_size and
        val % 4 == 0
    )

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

def decode_bytes(data: bytes) -> str:
    """Decode bytes to string, replacing non-printable characters."""
    return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)

def interpret_emi_cona_val(val: int) -> Dict[str, Any]:
    """Interpret EMI_CONA_VAL."""
    return {
        'dual_rank': bool(val & (1 << 16)),
        'bus_width': 16 if val & (1 << 2) else 32,
        'burst_mode': bool(val & 1)
    }

def interpret_dram_rank_size(sizes: List[int]) -> Tuple[List[str], int]:
    """Interpret DRAM rank sizes."""
    rank_sizes = []
    total = 0
    for i, size in enumerate(sizes):
        if size == 0:
            rank_sizes.append('Disabled')
        else:
            rank_sizes.append(f"{size // (1024 * 1024)} MB")
            total += size // (1024 * 1024)
    return rank_sizes, total

def disassemble_code(data: bytes, offset: int, file_size: int, max_instructions: int = 10) -> Dict[str, Any]:
    """Disassemble code section using capstone."""
    if not CAPSTONE_AVAILABLE:
        return {'instructions': [], 'functions': [], 'insights': ['Capstone not available']}
    analysis = {'instructions': [], 'functions': [], 'insights': []}
    try:
        md_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        md_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        instructions = []
        for mode, md in [(CS_MODE_ARM, md_arm), (CS_MODE_THUMB, md_thumb)]:
            for i, (addr, size, mnemonic, op_str) in enumerate(md.disasm_lite(data, offset)):
                if i >= max_instructions:
                    break
                instructions.append(f"0x{addr:08X}: {mnemonic} {op_str}")
                if mnemonic in ('bl', 'bx', 'b'):
                    try:
                        target = int(op_str.replace('#', ''), 16) if op_str.startswith('#') else 0
                        if 0x1000 < target < file_size:
                            analysis['functions'].append(f"0x{addr:08X}: Branch to 0x{target:08X}")
                    except ValueError:
                        pass
        analysis['instructions'] = instructions[:max_instructions]
        if instructions:
            analysis['insights'].append("Significant code section detected. Review for bootloader logic.")
    except Exception as e:
        analysis['insights'].append(f"Disassembly error: {str(e)}")
    return analysis

def extract_section(data: bytes, start: int, size: int, output_dir: Path, name: str, analyze: bool = False, file_size: int = 0) -> Dict[str, Any]:
    """Extract a data section to a file with optional analysis."""
    if size <= 0:
        logger.error(f"Invalid section size {size} for {name} at 0x{start:X}, skipping extraction")
        return {'path': None, 'size': 0, 'status': 'Invalid Size'}
    
    if start + size > len(data):
        logger.warning(f"Section {name} at 0x{start:X} exceeds file size, truncating to {len(data) - start} bytes")
        size = len(data) - start
    
    section = data[start:start + size]
    output_path = output_dir / f"{name}_{start:08X}_{size}.bin"
    with output_path.open('wb') as f:
        f.write(section)
    logger.info(f"Extracted section '{name}' at 0x{start:X} (size: {size} bytes) to {output_path.name}")
    
    analysis = {'path': str(output_path), 'size': size}
    if analyze and size > 4:
        analysis['strings'] = [s for s in re.findall(b'[\x20-\x7e]{5,}', section)]
        analysis.update(disassemble_code(section, start, file_size, max_instructions=10))
        analysis['reserved'] = {}
    return analysis

def analyze_remaining_data(data: bytes, start: int, output_dir: Path, file_size: int, max_size: int = 1024*1024) -> Dict[str, Any]:
    """Analyze remaining data for strings, code, and pointers."""
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
    
    analysis['strings'] = [f"0x{start + m.start():X}: {m.group().decode('ascii')}"
                          for m in re.finditer(b'[\x20-\x7e]{5,}', data)]
    
    for i in range(0, len(data) - 3, 4):
        val = struct.unpack_from('<I', data, i)[0]
        if Config.POTENTIAL_PTR(data[i:i+4], file_size):
            analysis['pointers'].append(f"0x{start + i:X}: 0x{val:08X}")
    
    if CAPSTONE_AVAILABLE:
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        code_start = None
        instructions = []
        invalid_count = 0
        i = 0
        while i < len(data) - 3:
            if (start + i) % 4 != 0:
                i += 1
                continue
            chunk = data[i:i+4]
            disasm_result = list(md.disasm(chunk, start + i))
            if disasm_result and not all(ins.mnemonic == 'andeq' and ins.op_str == 'r0, r0, r0' for ins in disasm_result):
                if code_start is None:
                    code_start = start + i
                instructions.extend(f"0x{a:08X}: {m} {o}" for a, s, m, o in md.disasm_lite(chunk, start + i))
                invalid_count = 0
            else:
                invalid_count += 4
                if code_start is not None and (invalid_count >= 8 or i + 4 >= len(data)):
                    section_size = min(i - (code_start - start), Config.MAX_CODE_SECTION_SIZE, len(data) - (code_start - start))
                    if section_size > 0:
                        disasm_analysis = disassemble_code(data[code_start - start:code_start - start + section_size], code_start, file_size, max_instructions=10)
                        analysis['code_sections'].append({
                            'offset': f"0x{code_start:X}",
                            'size': section_size,
                            'instructions': disasm_analysis['instructions'][:10],
                            'functions': disasm_analysis['functions'],
                            'insights': disasm_analysis['insights']
                        })
                        extract_section(data, code_start - start, section_size, output_dir, "CODE_SECTION", analyze=False, file_size=file_size)
                    code_start = None
                    instructions = []
            i += 4
        
        if code_start is not None and instructions:
            section_size = min(len(data) - (code_start - start), Config.MAX_CODE_SECTION_SIZE)
            if section_size > 0:
                disasm_analysis = disassemble_code(data[code_start - start:code_start - start + section_size], code_start, file_size, max_instructions=10)
                analysis['code_sections'].append({
                    'offset': f"0x{code_start:X}",
                    'size': section_size,
                    'instructions': disasm_analysis['instructions'][:10],
                    'functions': disasm_analysis['functions'],
                    'insights': disasm_analysis['insights']
                })
                extract_section(data, code_start - start, section_size, output_dir, "CODE_SECTION", analyze=False, file_size=file_size)
    
    if analysis['entropy'] > 0.9:
        analysis['insights'].append("High entropy detected: Possible encrypted or compressed section")
    if analysis['pointers']:
        analysis['insights'].append(f"Pointers found: May reference offsets within file (size: {file_size} bytes)")
    if analysis['code_sections']:
        analysis['insights'].append("Executable code detected: Potential bootloader logic or initialization routines")
    
    return analysis

def print_element(element: Dict[str, Any], index: int) -> None:
    """Print details of a parsed element."""
    logger.info(f"--------Start Element {index}--------")
    if element.get('warnings'):
        for warning in element['warnings']:
            logger.warning(warning)
    logger.info(f"Offset: 0x{element['offset']:X}")
    logger.info(f"Type: {element['type']}")
    logger.info(f"eMMC ID: {element['emmc_id']} (Raw: {element['raw_emmc_id'].hex()}, Rev: {element['emmc_rev']})")
    logger.info(f"Firmware ID: {element['fw_id']}")
    logger.info(f"EMI_CONA_VAL: 0x{element['emi_cona_val']:08X} (Dual Rank: {element['emi_cona']['dual_rank']}, "
                f"Bus Width: {element['emi_cona']['bus_width']} bits, Burst: {'Enabled' if element['emi_cona']['burst_mode'] else 'Disabled'})")
    logger.info(f"DRAMC_ACTIM_VAL: 0x{element['dramc_actim_val']:08X} (Est. Freq: {element['est_freq']})")
    rank_sizes, total = interpret_dram_rank_size(element['dram_rank_size'])
    logger.info(f"DRAM Rank Size: {', '.join(rank_sizes)} (Total: {total} MB)")
    logger.info(f"Reserved: {element['reserved'].hex()}")
    logger.info(f"Reserved Analysis: {element['reserved_analysis']}")
    for rec in element.get('recommendations', []):
        logger.info(f"Recommendations: {rec}")
    logger.info(f"--------End Element {index}--------")

def parse(data: bytes, output_dir: Path, file_size: int) -> Dict[str, Any]:
    """Parse the bootloader file."""
    analysis = {
        'sections': [],
        'elements': [],
        'emmc_vendors': set(),
        'memory_types': set(),
        'strings': [],
        'dram_sizes': {},
        'total_elements': 0,
        'valid_elements': 0,
        'empty_elements': 0,
        'corrupted_elements': 0
    }
    
    logger.info(f"Processing bootloader (size: {len(data)} bytes)")
    
    # Extract known sections
    for name, pattern in Config.SECTION_PATTERNS.items():
        for match in pattern.finditer(data):
            start = match.start()
            size = len(match.group()) if name != 'MTK_BLOADER_INFO_HEADER' else 112
            section_analysis = extract_section(data, start, size, output_dir, name, analyze=True, file_size=file_size)
            analysis['sections'].append(section_analysis)
            if section_analysis.get('strings'):
                analysis['strings'].extend(section_analysis['strings'])
    
    # Parse MTK_BLOADER_INFO header
    mtk_bloader = next((s for s in analysis['sections'] if 'MTK_BLOADER_INFO_' in s.get('path', '') and s.get('size') == 20), None)
    offset = None
    if mtk_bloader:
        offset = int(mtk_bloader['path'].split('_')[-2], 16)
        header_data = data[offset:offset+112]
        if len(header_data) < 112:
            logger.error(f"Insufficient data for MTK_BLOADER_INFO header at 0x{offset:X}, expected 112 bytes, got {len(header_data)}")
            analysis['header'] = None
        else:
            try:
                header = {
                    'version': header_data[:16].decode('ascii').strip('\x00'),
                    'file_name': header_data[16:80].decode('ascii').strip('\x00'),
                    'model': header_data[16:80].decode('ascii').strip('\x00').split('.')[0],
                    'hex_1': struct.unpack_from('<I', header_data, 80)[0],
                    'hex_2': struct.unpack_from('<I', header_data, 84)[0],
                    'hex_3': struct.unpack_from('<I', header_data, 88)[0],
                    'mtk_bin': header_data[92:100].decode('ascii').strip('\x00'),
                    'total_configs': struct.unpack_from('<I', header_data, 108)[0]
                }
                logger.info(f"Header: {header['version']} (Version: {header['version'].split('_v')[-1]})")
                logger.info(f"File Name: {header['file_name']}")
                logger.info(f"Model: {header['model']}")
                logger.info(f"hex_1: 0x{header['hex_1']:X}")
                logger.info(f"hex_2: 0x{header['hex_2']:X}")
                logger.info(f"hex_3: 0x{header['hex_3']:X}")
                logger.info(f"mtk_bin: {header['mtk_bin']}")
                logger.info(f"Total Configurations: {header['total_configs']}")
                analysis['header'] = header
            except (UnicodeDecodeError, struct.error) as e:
                logger.error(f"Failed to parse MTK_BLOADER_INFO header at 0x{offset:X}: {str(e)}")
                analysis['header'] = None
    else:
        logger.warning("MTK_BLOADER_INFO section not found, skipping header and element parsing")
    
    # Parse elements if header is valid and total_configs > 0
    if mtk_bloader and analysis.get('header') and analysis['header']['total_configs'] > 0:
        offset += 112
        for i in range(analysis['header']['total_configs']):
            element_data = data[offset:offset+188]
            if len(element_data) < 188:
                logger.warning(f"Element {i} at 0x{offset:X} truncated, skipping")
                analysis['corrupted_elements'] += 1
                offset += 188
                continue
            
            warnings = []
            try:
                emmc_id_len = struct.unpack_from('<I', element_data, 4)[0]
                fw_id_len = struct.unpack_from('<I', element_data, 8)[0]
                if emmc_id_len > Config.MAX_EMMC_ID_LEN or fw_id_len > Config.MAX_FW_ID_LEN:
                    warnings.append(f"Capped invalid lengths at offset 0x{offset:X}: eMMC={emmc_id_len} to {Config.MAX_EMMC_ID_LEN}, FW={fw_id_len} to {Config.MAX_FW_ID_LEN}")
                    emmc_id_len = min(emmc_id_len, Config.MAX_EMMC_ID_LEN)
                    fw_id_len = min(fw_id_len, Config.MAX_FW_ID_LEN)
                
                element = {
                    'offset': offset,
                    'type': struct.unpack_from('<I', element_data, 0)[0],
                    'emmc_id': decode_bytes(element_data[12:12+emmc_id_len]),
                    'raw_emmc_id': element_data[12:28],
                    'emmc_rev': decode_bytes(element_data[28:36]),
                    'fw_id': decode_bytes(element_data[36:36+fw_id_len]),
                    'emi_cona_val': struct.unpack_from('<I', element_data, 44)[0],
                    'dramc_actim_val': struct.unpack_from('<I', element_data, 48)[0],
                    'dram_rank_size': list(struct.unpack_from('<4I', element_data, 52)),
                    'reserved': element_data[148:188]
                }
                
                emmc_id_prefix = element['raw_emmc_id'][:3]
                element['emmc_id'] = Config.EMMC_VENDORS.get(emmc_id_prefix, f"Unknown (0x{emmc_id_prefix.hex()})")
                analysis['emmc_vendors'].add(element['emmc_id'])
                analysis['memory_types'].add(f"Unknown (0x{element['type']:X})")
                
                element['emi_cona'] = interpret_emi_cona_val(element['emi_cona_val'])
                element['est_freq'] = 'Unknown'
                rank_sizes, total = interpret_dram_rank_size(element['dram_rank_size'])
                element['total_dram'] = total
                analysis['dram_sizes'][total] = analysis['dram_sizes'].get(total, 0) + 1
                
                reserved_entropy = sum(element['reserved'].count(b) for b in set(element['reserved'])) / len(element['reserved']) if element['reserved'] else 0
                element['reserved_analysis'] = 'Low variety: Possible repeating pattern or table' if reserved_entropy < 0.5 else \
                                             'Possible string or identifier' if any(b'[\x20-\x7e]{5,}' in element['reserved']) else \
                                             'High entropy: Possible encrypted data'
                element['recommendations'] = []
                if reserved_entropy < 0.5:
                    element['recommendations'].append(f"Possible structure in reserved field: {element['reserved_analysis']}")
                
                for j in range(0, len(element['reserved']) - 3, 4):
                    val = struct.unpack_from('<I', element['reserved'], j)[0]
                    if Config.POTENTIAL_PTR(element['reserved'][j:j+4], file_size):
                        element['reserved_analysis'] += f", Pointer: 0x{val:08X}"
                        element['recommendations'].append(f"Potential pointers found in reserved field. Cross-reference with file offsets.")
                
                if element['emi_cona_val'] == 0 and element['dramc_actim_val'] == 0 and all(s == 0 for s in element['dram_rank_size']):
                    warnings.append(f"Element at offset 0x{offset:X} appears empty or disabled")
                    analysis['empty_elements'] += 1
                else:
                    analysis['valid_elements'] += 1
                
                if element['type'] not in {0x203, 0x0}:
                    warnings.append(f"Unusual memory type at offset 0x{offset:X}: 0x{element['type']:X}")
                
                element['warnings'] = warnings
                print_element(element, i)
                section_analysis = extract_section(data, offset, 188, output_dir, f"ELEMENT_{i}", analyze=True, file_size=file_size)
                analysis['elements'].append({**element, **section_analysis})
                if section_analysis.get('strings'):
                    analysis['strings'].extend(section_analysis['strings'])
                
                analysis['total_elements'] += 1
                offset += 188
            except Exception as e:
                logger.error(f"Failed to parse element {i} at 0x{offset:X}: {str(e)}")
                analysis['corrupted_elements'] += 1
                offset += 188
    else:
        logger.warning("Skipping element parsing due to missing or invalid MTK_BLOADER_INFO header")
    
    # Extract size field only if offset is defined
    if offset is not None and offset + 4 <= len(data):
        size_field_offset = offset
        size_field = struct.unpack_from('<I', data, size_field_offset)[0]
        section_analysis = extract_section(data, size_field_offset, 4, output_dir, "SIZE_FIELD", file_size=file_size)
        analysis['sections'].append(section_analysis)
        logger.info(f"Size: {size_field}")
        offset += 4
    else:
        logger.warning("Skipping SIZE_FIELD extraction due to undefined offset or insufficient data")
    
    # Analyze remaining data
    if offset is not None and offset < len(data):
        remaining_data = data[offset:]
        if remaining_data:
            section_analysis = extract_section(data, offset, len(remaining_data), output_dir, "REMAINING_DATA", analyze=True, file_size=file_size)
            analysis['sections'].append(section_analysis)
            remaining_analysis = analyze_remaining_data(remaining_data, offset, output_dir, file_size)
            analysis['sections'].append(remaining_analysis)
            if remaining_analysis.get('strings'):
                analysis['strings'].extend(remaining_analysis['strings'])
    
    return analysis

def main():
    parser = argparse.ArgumentParser(description="Analyze MTK bootloader files.")
    parser.add_argument('file', type=str, help="Bootloader file to analyze")
    parser.add_argument('--output-dir', type=str, default='output', help="Output directory for extracted files")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose logging")
    parser.add_argument('--json', action='store_true', help="Generate JSON output")
    parser.add_argument('--markdown', action='store_true', help="Generate Markdown output")
    parser.add_argument('--log-dir', type=str, default='logs', help="Directory for log files")
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    log_dir = Path(args.log_dir)
    log_dir.mkdir(exist_ok=True)
    
    file_path = Path(args.file)
    with file_path.open('rb') as f:
        data = f.read()
    
    analysis = parse(data, output_dir, len(data))
    
    valid_elements = [e for e in analysis['elements'] if e.get('total_dram', 0) > 0]
    with (output_dir / 'flash_tool_memory_config.txt').open('w') as f:
        for i, element in enumerate(valid_elements):
            f.write(f"Element {i}:\n")
            f.write(f"  Offset: 0x{element['offset']:X}\n")
            f.write(f"  eMMC ID: {element['emmc_id']}\n")
            f.write(f"  EMI_CONA: 0x{element['emi_cona_val']:08X}\n")
            f.write(f"  DRAMC_ACTIM: 0x{element['dramc_actim_val']:08X}\n")
            f.write(f"  DRAM Rank Size: {', '.join(interpret_dram_rank_size(element['dram_rank_size'])[0])}\n")
            f.write("\n")
    logger.info(f"Generated SP Flash Tool config at flash_tool_memory_config.txt")
    
    if args.json:
        with (output_dir / 'analysis.json').open('w') as f:
            json.dump(analysis, f, indent=2)
    
    if args.markdown:
        md_content = "# Bootloader Analysis Report\n\n"
        md_content += f"**File**: {file_path.name}\n"
        md_content += f"**Size**: {len(data)} bytes\n\n"
        md_content += "## Summary\n"
        md_content += f"- **Supported eMMC Vendors**: {', '.join(analysis['emmc_vendors'])}\n"
        md_content += f"- **Memory Types**: {', '.join(analysis['memory_types'])}\n"
        md_content += f"- **Total Elements**: {analysis['total_elements']}\n"
        md_content += f"- **Valid Elements**: {analysis['valid_elements']}\n"
        md_content += f"- **Empty or Disabled Elements**: {analysis['empty_elements']}\n"
        md_content += f"- **Corrupted Elements**: {analysis['corrupted_elements']}\n"
        md_content += "\n## DRAM Size Distribution\n"
        for size, count in sorted(analysis['dram_sizes'].items()):
            md_content += f"- {size} MB: {'*' * count} ({count} elements)\n"
        md_content += "\n## Extracted Sections\n"
        for section in analysis['sections']:
            if section.get('path'):
                md_content += f"- {Path(section['path']).name} ({section['size']} bytes)\n"
                if section.get('strings'):
                    md_content += "  **Strings Found**:\n"
                    for s in section['strings']:
                        md_content += f"    - {s.decode('ascii') if isinstance(s, bytes) else s}\n"
                if section.get('code_sections'):
                    for cs in section['code_sections']:
                        md_content += f"  **Code Section** at {cs['offset']} ({cs['size']} bytes):\n"
                        for ins in cs['instructions']:
                            md_content += f"    - {ins}\n"
                        for insight in cs['insights']:
                            md_content += f"    - {insight}\n"
                if section.get('pointers'):
                    md_content += "  **Pointers Found**:\n"
                    for p in section['pointers']:
                        md_content += f"    - {p}\n"
        md_content += "\n## Recommendations\n"
        if analysis['strings']:
            md_content += "- Found strings, code, or pointers in REMAINING_DATA. Review for additional firmware insights.\n"
        if analysis['emmc_vendors']:
            md_content += f"- Supports {len(analysis['emmc_vendors'])} eMMC vendors: {', '.join(analysis['emmc_vendors'])}. Verify storage compatibility.\n"
        for element in analysis['elements']:
            for rec in element.get('recommendations', []):
                md_content += f"- {rec}\n"
        with (output_dir / 'analysis.md').open('w') as f:
            f.write(md_content)
    
    logger.info("Analysis Summary:")
    logger.info(f"Supported eMMC Vendors: {', '.join(analysis['emmc_vendors'])}")
    logger.info(f"Memory Types: {', '.join(analysis['memory_types'])}")
    logger.info(f"Total Elements: {analysis['total_elements']}")
    logger.info(f"Valid Elements: {analysis['valid_elements']}")
    logger.info(f"Empty or Disabled Elements: {analysis['empty_elements']}")
    logger.info(f"Corrupted Elements: {analysis['corrupted_elements']}")
    logger.info("DRAM Size Distribution:")
    for size, count in sorted(analysis['dram_sizes'].items()):
        logger.info(f"  {size} MB: {'*' * count} ({count} elements)")
    for section in analysis['sections']:
        if section.get('path'):
            logger.info(f"Extracted Section: {Path(section['path']).name} ({section['size']} bytes)")
            if section.get('strings'):
                logger.info("Strings Found:")
                for s in section['strings']:
                    logger.info(f"  {s.decode('ascii') if isinstance(s, bytes) else s}")
    for section in analysis['sections']:
        if section.get('code_sections'):
            for cs in section['code_sections']:
                logger.info(f"Code Sections Found:")
                logger.info(f"  Offset: {cs['offset']}, Size: {cs['size']} bytes")
                for ins in cs['instructions']:
                    logger.info(f"    {ins}")
                for insight in cs['insights']:
                    logger.info(f"  Insights: {insight}")
    for section in analysis['sections']:
        if section.get('pointers'):
            logger.info(f"Pointers Found:")
            for p in section['pointers']:
                logger.info(f"  {p}")
    for section in analysis['sections']:
        for insight in section.get('insights', []):
            logger.info(f"Recommendation: {insight}")
    for element in analysis['elements']:
        for rec in element.get('recommendations', []):
            logger.info(f"Recommendation: {rec}")

if __name__ == "__main__":
    main()
