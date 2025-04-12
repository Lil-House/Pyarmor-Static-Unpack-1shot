import logging
import os
from typing import List, Tuple, Optional, Dict, Any

# Import constants from shot
try:
    from shot import (
        PYARMOR_MODE_STANDARD, PYARMOR_MODE_ADVANCED, 
        PYARMOR_MODE_SUPER, PYARMOR_MODE_VM_ADVANCED, 
        PYARMOR_MODE_VM_SUPER
    )
except ImportError:
    # Define them here if shot module is not available
    PYARMOR_MODE_STANDARD = 0
    PYARMOR_MODE_ADVANCED = 1
    PYARMOR_MODE_SUPER = 2
    PYARMOR_MODE_VM_ADVANCED = 3
    PYARMOR_MODE_VM_SUPER = 4


def ascii_ratio(data: bytes) -> float:
    return sum(32 <= c < 127 for c in data) / len(data)


def detect_pyarmor_mode(data: bytes) -> int:
    """
    Detect the PyArmor obfuscation mode from the data.
    
    Returns:
        int: PYARMOR_MODE_* constant
    """
    # Super Mode detection (structure is different)
    if data[0:4] == b'PYSA':  # Potential Super Mode marker
        return PYARMOR_MODE_SUPER
    
    # Check for VM mode by specific markers in the data
    vm_marker_offset = data.find(b'pyarmor-vm')
    if vm_marker_offset != -1:
        # Check if it's VM+Super or VM+Advanced
        if data.find(b'pyarmor-super') != -1:
            return PYARMOR_MODE_VM_SUPER
        else:
            return PYARMOR_MODE_VM_ADVANCED
    
    # Check for Advanced Mode by examining specific metadata
    try:
        adv_flag = int.from_bytes(data[24:28], 'little')
        if adv_flag & 0x1:  # Advanced mode flag bit
            return PYARMOR_MODE_ADVANCED
    except:
        pass
    
    # Default to standard mode
    return PYARMOR_MODE_STANDARD


def detect_pyarmor_restrict_mode(data: bytes) -> Optional[int]:
    """
    Attempt to detect PyArmor restrict mode from data.
    
    Returns:
        Optional[int]: Detected restrict mode (0-5) or None if unknown
    """
    try:
        # Restrict mode is usually stored in a specific location in the metadata
        offset = 52  # Common offset for restrict mode flag
        restrict_flag = data[offset]
        
        # Validation - restrict mode should be 0-5
        if 0 <= restrict_flag <= 5:
            return restrict_flag
    except:
        pass
    
    return None


def is_bcc_mode(data: bytes) -> bool:
    """
    Check if the data is likely in BCC mode.
    BCC (Byte Code Conversion) mode converts Python functions to C functions.
    
    Returns:
        bool: True if BCC mode is detected
    """
    try:
        # BCC mode often has a specific marker
        if b'__pyarmor_bcc__' in data:
            return True
            
        # Check for BCC mode by examining key bytes
        offset = 0x58  # Common offset for BCC metadata
        if len(data) > offset + 4:
            bcc_part_length = int.from_bytes(data[offset:offset+4], 'little')
            
            # If bcc_part_length is non-zero and reasonable, it's likely BCC mode
            if 0 < bcc_part_length < len(data) - 64:
                return True
    except:
        pass
    
    return False


def source_as_file(file_path: str) -> List[bytes] | None:
    try:
        with open(file_path, 'r') as f:
            co = compile(f.read(), '<str>', 'exec')
            data = [i for i in co.co_consts if type(i) is bytes
                    and i.startswith(b'PY00') and len(i) > 64]
            return data
    except:
        return None


def source_as_lines(file_path: str) -> List[bytes] | None:
    data = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                try:
                    co = compile(line, '<str>', 'exec')
                    data.extend([i for i in co.co_consts if type(i) is bytes
                                 and i.startswith(b'PY00') and len(i) > 64])
                except:
                    # ignore not compilable lines
                    pass
    except:
        return None
    return data


def find_data_from_bytes(data: bytes, max_count=-1) -> List[bytes]:
    result = []
    idx = 0
    while len(result) != max_count:
        idx = data.find(b'PY00')
        if idx == -1:
            break
        data = data[idx:]
        if len(data) < 64:
            break
        header_len = int.from_bytes(data[28:32], 'little')
        body_len = int.from_bytes(data[32:36], 'little')
        if header_len > 256 or body_len > 0xFFFFF or header_len + body_len > len(data):
            # compressed or coincident, skip
            data = data[5:]
            continue
        result.append(data[:header_len + body_len])

        # maybe followed by data for other Python versions from the same file,
        # we do not extract them
        followed_by_another_equivalent = int.from_bytes(
            data[56:60], 'little') != 0
        data = data[header_len + body_len:]
        while followed_by_another_equivalent \
                and data.startswith(b'PY00') \
                and len(data) >= 64:
            header_len = int.from_bytes(data[28:32], 'little')
            body_len = int.from_bytes(data[32:36], 'little')
            followed_by_another_equivalent = int.from_bytes(
                data[56:60], 'little') != 0
            data = data[header_len + body_len:]
    return result


def find_super_mode_data(data: bytes, max_count=-1) -> List[bytes]:
    """
    Find PyArmor Super Mode data markers in binary data.
    Super Mode has a different structure than standard mode.
    
    Args:
        data: Binary data to search
        max_count: Maximum number of results to return (-1 for unlimited)
        
    Returns:
        List of extracted Super Mode obfuscated data chunks
    """
    result = []
    idx = 0
    while len(result) != max_count:
        # Super Mode typically has a different marker
        idx = data.find(b'PYSA')
        if idx == -1:
            break
            
        data = data[idx:]
        if len(data) < 64:
            break
            
        # Super Mode has a different header structure
        try:
            header_offset = 8
            header_length = int.from_bytes(data[header_offset:header_offset+4], 'little')
            
            # Basic validation
            if header_length > 256 or header_length > len(data):
                data = data[4:]
                continue
                
            # Extract total length - may be encoded differently in Super Mode
            content_offset = header_offset + 4 + header_length
            total_length = 0
            
            # Try different methods to determine total length
            if len(data) >= content_offset + 4:
                content_length = int.from_bytes(data[content_offset:content_offset+4], 'little')
                if 0 < content_length < 0xFFFFF:
                    total_length = content_offset + content_length
            
            # If couldn't determine length, use a heuristic
            if total_length == 0:
                # Look for common end markers or use reasonable default
                end_idx = data.find(b'PYEND')
                if end_idx > content_offset:
                    total_length = end_idx + 5
                else:
                    # Default to a reasonable chunk
                    total_length = min(len(data), content_offset + 0x10000)
            
            # Extract the data
            result.append(data[:total_length])
            data = data[total_length:]
        except:
            # If parsing fails, skip this marker
            data = data[4:]
            
    return result


def nuitka_package(head: bytes, relative_path: str) -> None | List[Tuple[str, bytes]]:
    first_occurrence = head.find(b'PY00')
    if first_occurrence == -1:
        # Check for Super Mode as well
        first_occurrence = head.find(b'PYSA')
        if first_occurrence == -1:
            return None
            
    last_dot_bytecode = head.rfind(b'.bytecode\x00', 0, first_occurrence)
    if last_dot_bytecode == -1:
        return None
    length = int.from_bytes(
        head[last_dot_bytecode-4:last_dot_bytecode], 'little')
    end = last_dot_bytecode + length
    cur = last_dot_bytecode
    result = []
    while cur < end:
        module_name_len = head.find(b'\x00', cur, end) - cur
        module_name = head[cur:cur + module_name_len].decode('utf-8')
        cur += module_name_len + 1
        module_len = int.from_bytes(head[cur:cur + 4], 'little')
        cur += 4
        
        # Check format - could be standard or super mode
        if head[cur:cur+4] == b'PYSA':
            # Super Mode
            module_data = find_super_mode_data(head[cur:cur + module_len], 1)
        else:
            # Standard Mode
            module_data = find_data_from_bytes(head[cur:cur + module_len], 1)
            
        if module_data:
            result.append((os.path.join(relative_path.rstrip(
                '/\\') + '.1shot.ext', module_name), module_data[0]))
        cur += module_len
    if result:
        logger = logging.getLogger('detect')
        logger.info(f'Found data in Nuitka package: {relative_path}')
        return result
    return None


def detect_process(file_path: str, relative_path: str) -> None | List[Tuple[str, bytes]]:
    '''
    Returns a list of (relative_path, bytes_raw) tuples, or None.
    Do not raise exceptions.
    '''
    logger = logging.getLogger('detect')

    try:
        with open(file_path, 'rb') as f:
            head = f.read(16 * 1024 * 1024)
    except:
        logger.error(f'Failed to read file: {relative_path}')
        return None

    # Check for all PyArmor markers
    if (b'__pyarmor__' not in head and 
        b'pyarmor-vax' not in head and 
        b'pyarmor-super' not in head and
        b'PYSA' not in head):
        # no need to dig deeper
        return None

    if ascii_ratio(head[:2048]) >= 0.9:
        # the whole file may not be compiled, but we can still try some lines;
        # None means failure (then we make another try),
        # empty list means success but no data found (then we skip this file)
        result = source_as_file(file_path)
        if result is None:
            result = source_as_lines(file_path)
        if result is None:
            return None

        match len(result):
            case 0:
                return None
            case 1:
                logger.info(f'Found data in source: {relative_path}')
                return [(relative_path, result[0])]
            case _:
                logger.info(f'Found data in source: {relative_path}')
                return [(f'{relative_path}__{i}', result[i]) for i in range(len(result))]

    # binary file
    # ignore data after 16MB, before we have a reason to read more

    if b'Error, corrupted constants object' in head:
        # an interesting special case: packer put armored data in a Nuitka package
        # we can know the exact module names, instead of adding boring __0, __1, ...
        return nuitka_package(head, relative_path)

    # Try to detect PyArmor mode
    has_super_mode = b'PYSA' in head or b'pyarmor-super' in head
    
    # Extract data based on detected format
    if has_super_mode:
        logger.info(f'Detected Super Mode in file: {relative_path}')
        result = find_super_mode_data(head)
        
        # Fallback to standard detection if super mode detection finds nothing
        if not result:
            result = find_data_from_bytes(head)
    else:
        result = find_data_from_bytes(head)

    match len(result):
        case 0:
            return None
        case 1:
            # Check and report mode
            mode = detect_pyarmor_mode(result[0])
            if mode != PYARMOR_MODE_STANDARD:
                mode_names = {
                    PYARMOR_MODE_ADVANCED: "Advanced Mode",
                    PYARMOR_MODE_SUPER: "Super Mode",
                    PYARMOR_MODE_VM_ADVANCED: "VM Advanced Mode",
                    PYARMOR_MODE_VM_SUPER: "VM Super Mode"
                }
                logger.info(f'Detected PyArmor {mode_names.get(mode, f"Unknown Mode ({mode})")} in: {relative_path}')
            
            # Check for BCC mode
            if is_bcc_mode(result[0]):
                logger.info(f'Detected BCC mode in: {relative_path}')
            
            logger.info(f'Found data in binary: {relative_path}')
            return [(relative_path, result[0])]
        case _:
            logger.info(f'Found data in binary: {relative_path}')
            return [(f'{relative_path}__{i}', result[i]) for i in range(len(result))]
