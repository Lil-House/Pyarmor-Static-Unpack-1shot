import logging
import os
from typing import List, Tuple


def ascii_ratio(data: bytes) -> float:
    return sum(32 <= c < 127 for c in data) / len(data)


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


def nuitka_package(head: bytes, relative_path: str) -> None | List[Tuple[str, bytes]]:
    first_occurrence = head.find(b'PY00')
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

    if b'__pyarmor__' not in head:
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

    result = find_data_from_bytes(head)
    match len(result):
        case 0:
            return None
        case 1:
            logger.info(f'Found data in binary: {relative_path}')
            return [(relative_path, result[0])]
        case _:
            logger.info(f'Found data in binary: {relative_path}')
            return [(f'{relative_path}__{i}', result[i]) for i in range(len(result))]
