import argparse
from Crypto.Cipher import AES
import logging
import os
import subprocess
from typing import Dict, List, Tuple

from detect import detect_process
from runtime import RuntimeInfo


SUBPROCESS_TIMEOUT = 30


def general_aes_ctr_decrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=2)
    return cipher.decrypt(data)


def decrypt_process(runtimes: Dict[str, RuntimeInfo], sequences: List[Tuple[str, bytes]], args):
    logger = logging.getLogger('shot')
    output_dir: str = args.output_dir or args.directory
    for path, data in sequences:
        try:
            serial_number = data[2:8].decode('utf-8')
            runtime = runtimes[serial_number]
            logger.info(f'Decrypting: {serial_number} ({path})')

            dest_path = os.path.join(output_dir, path) if output_dir else path
            dest_dir = os.path.dirname(dest_path)
            if not os.path.exists(dest_dir):
                os.makedirs(dest_dir)

            if args.export_raw_data:
                with open(dest_path + '.1shot.raw', 'wb') as f:
                    f.write(data)

            cipher_text_offset = int.from_bytes(data[28:32], 'little')
            cipher_text_length = int.from_bytes(data[32:36], 'little')
            nonce = data[36:40] + data[44:52]
            with open(dest_path + '.1shot.seq', 'wb') as f:
                f.write(b'\xa1' + runtime.runtime_aes_key)
                f.write(b'\xa2' + runtime.mix_str_aes_nonce())
                f.write(b'\xf0\xff')
                f.write(data[:cipher_text_offset])
                f.write(general_aes_ctr_decrypt(
                    data[cipher_text_offset:cipher_text_offset+cipher_text_length], runtime.runtime_aes_key, nonce))
                f.write(data[cipher_text_offset+cipher_text_length:])

            exe_name = 'pyarmor-1shot.exe' if os.name == 'nt' else 'pyarmor-1shot'
            exe_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), exe_name)
            # TODO: multi process
            sp = subprocess.run(
                [
                    exe_path,
                    dest_path + '.1shot.seq',
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=SUBPROCESS_TIMEOUT,
            )
            stdout = sp.stdout.decode('latin-1').splitlines()
            stderr = sp.stderr.decode('latin-1').splitlines()
            for line in stdout:
                logger.warning(f'PYCDC: {line} ({path})')
            for line in stderr:
                if line.startswith((
                    'Warning: Stack history is empty',
                    'Warning: Stack history is not empty',
                    'Warning: block stack is not empty',
                )):
                    if args.show_warn_stack or args.show_all:
                        logger.warning(f'PYCDC: {line} ({path})')
                elif line.startswith('Unsupported opcode:'):
                    if args.show_err_opcode or args.show_all:
                        logger.error(f'PYCDC: {line} ({path})')
                elif line.startswith('Something TERRIBLE happened'):
                    if args.show_all:
                        logger.error(f'PYCDC: {line} ({path})')
                else:
                    logger.error(f'PYCDC: {line} ({path})')
            if sp.returncode != 0:
                logger.warning(f'PYCDC returned {sp.returncode} ({path})')
                continue
        except Exception as e:
            logger.error(f'Decrypt failed: {e} ({path})')
            continue


def parse_args():
    parser = argparse.ArgumentParser(
        description='Pyarmor Static Unpack 1 Shot Entry')
    parser.add_argument(
        'directory',
        help='the "root" directory of obfuscated scripts',
        type=str,
    )
    parser.add_argument(
        '-r',
        '--runtime',
        help='path to pyarmor_runtime[.pyd|.so|.dylib]',
        type=str,  # argparse.FileType('rb'),
    )
    parser.add_argument(
        '-o',
        '--output-dir',
        help='save output files in another directory instead of in-place, with folder structure remain unchanged',
        type=str,
    )
    parser.add_argument(
        '--export-raw-data',
        help='save data found in source files as-is',
        action='store_true',
    )
    parser.add_argument(
        '--show-all',
        help='show all pycdc errors and warnings',
        action='store_true',
    )
    parser.add_argument(
        '--show-err-opcode',
        help='show pycdc unsupported opcode errors',
        action='store_true',
    )
    parser.add_argument(
        '--show-warn-stack',
        help='show pycdc stack related warnings',
        action='store_true',
    )
    return parser.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)-8s %(asctime)-28s %(message)s',
    )
    logger = logging.getLogger('shot')

    print(r'''
 ____                                                                     ____ 
( __ )                                                                   ( __ )
 |  |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|  | 
 |  |   ____                                      _ ___  _          _     |  | 
 |  |  |  _ \ _  _  __ _ _ __ _ _ __   ___  _ _  / / __|| |_   ___ | |_   |  | 
 |  |  | |_) | || |/ _` | '__| ' `  \ / _ \| '_| | \__ \| ' \ / _ \| __|  |  | 
 |  |  |  __/| || | (_| | |  | || || | (_) | |   | |__) | || | (_) | |_   |  | 
 |  |  |_|    \_, |\__,_|_|  |_||_||_|\___/|_|   |_|___/|_||_|\___/ \__|  |  | 
 |  |         |__/                                                        |  | 
 |__|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|__| 
(____)                                                                   (____)

              For technology exchange only. Use at your own risk.
        GitHub: https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot
''')

    if args.runtime:
        specified_runtime = RuntimeInfo(args.runtime)
        print(specified_runtime)
        runtimes = {specified_runtime.serial_number: specified_runtime}
    else:
        specified_runtime = None
        runtimes = {}

    sequences: List[Tuple[str, bytes]] = []

    if args.output_dir and not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    if os.path.isfile(args.directory):
        if specified_runtime is None:
            logger.error('Please specify `pyarmor_runtime` file by `-r` if input is a file')
            return
        logger.info('Single file mode')
        result = detect_process(args.directory, args.directory)
        if result is None:
            logger.error('No armored data found')
            return
        sequences.extend(result)
        decrypt_process(runtimes, sequences, args)
        return  # single file mode ends here

    dir_path: str
    dirs: List[str]
    files: List[str]
    for dir_path, dirs, files in os.walk(args.directory, followlinks=False):
        if '.no1shot' in files:
            logger.info(f'Skipping {dir_path} because of `.no1shot`')
            dirs.clear()
            files.clear()
            continue
        for d in ['__pycache__', 'site-packages']:
            if d in dirs:
                dirs.remove(d)
        for file_name in files:
            if '.1shot.' in file_name:
                continue

            file_path = os.path.join(dir_path, file_name)
            relative_path = os.path.relpath(file_path, args.directory)

            if file_name.endswith('.pyz'):
                with open(file_path, 'rb') as f:
                    head = f.read(16 * 1024 * 1024)
                if b'PY00' in head \
                        and (not os.path.exists(file_path + '_extracted')
                             or len(os.listdir(file_path + '_extracted')) == 0):
                    logger.error(
                        f'A PYZ file containing armored data is detected, but the PYZ file has not been extracted by other tools. This error is not a problem with this tool. If the folder is extracted by Pyinstxtractor, please read the output information of Pyinstxtractor carefully. ({relative_path})')
                continue

            # is pyarmor_runtime?
            if specified_runtime is None \
                    and file_name.startswith('pyarmor_runtime') \
                    and file_name.endswith(('.pyd', '.so', '.dylib')):
                try:
                    new_runtime = RuntimeInfo(file_path)
                    runtimes[new_runtime.serial_number] = new_runtime
                    logger.info(
                        f'Found new runtime: {new_runtime.serial_number} ({file_path})')
                    print(new_runtime)
                    continue
                except:
                    pass

            result = detect_process(file_path, relative_path)
            if result is not None:
                sequences.extend(result)

    if not runtimes:
        logger.error('No runtime found')
        return
    if not sequences:
        logger.error('No armored data found')
        return
    decrypt_process(runtimes, sequences, args)


if __name__ == '__main__':
    main()
