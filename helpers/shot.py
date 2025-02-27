import argparse
from Crypto.Cipher import AES
import logging
import os
import subprocess

from runtime import RuntimeInfo


SUBPROCESS_TIMEOUT = 30


def general_aes_ctr_decrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=2)
    return cipher.decrypt(data)


def decrypt_process(runtimes: dict[str, RuntimeInfo], sequences: list[tuple[str, bytes]], output_dir: str = None):
    logger = logging.getLogger('shot')
    for path, data in sequences:
        try:
            serial_number = data[2:8].decode('utf-8')
            runtime = runtimes[serial_number]
            logger.info(f'Decrypting: {serial_number} ({path})')

            dest_path = os.path.join(output_dir, path) if output_dir else path
            dest_dir = os.path.dirname(dest_path)
            if not os.path.exists(dest_dir):
                os.makedirs(dest_dir)

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
            stdout = sp.stdout.decode().splitlines()
            stderr = sp.stderr.decode().splitlines()
            for line in stdout:
                logger.warning(f'STDOUT {line} ({path})')
            for line in stderr:
                if line.startswith('Warning'):
                    logger.warning(f'STDERR {line} ({path})')
                else:
                    logger.error(f'STDERR {line} ({path})')
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
    return parser.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)-8s %(asctime)-28s %(message)s',
    )
    logger = logging.getLogger('shot')

    print('''
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
''')

    if args.runtime:
        specified_runtime = RuntimeInfo(args.runtime)
        runtimes = {specified_runtime.serial_number: specified_runtime}
    else:
        specified_runtime = None
        runtimes = {}

    sequences: list[tuple[str, bytes]] = []

    if args.output_dir and not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    dir_path: str
    dirs: list[str]
    files: list[str]
    for dir_path, dirs, files in os.walk(args.directory, followlinks=False):
        for d in ['__pycache__', 'site-packages']:
            if d in dirs:
                dirs.remove(d)
        for file_name in files:
            if '.1shot.' in file_name:
                continue
            handled = False
            file_path = os.path.join(dir_path, file_name)
            relative_path = os.path.relpath(file_path, args.directory)

            # is pyarmor_runtime?
            if not handled \
                    and specified_runtime is None \
                    and file_name.startswith('pyarmor_runtime') \
                    and not file_name.endswith(('.lnk', '.i64', '.idb', '.id0', '.id1',
                                                '.id2', '.nam', '.til', '.bak')):
                try:
                    new_runtime = RuntimeInfo(file_path)
                    runtimes[new_runtime.serial_number] = new_runtime
                    logger.info(
                        f'Found new runtime: {new_runtime.serial_number} ({file_path})')
                    print(new_runtime)
                    handled = True
                except:
                    pass

            with open(file_path, 'rb') as f:
                beacon = f.read(16 * 1024 * 1024)

            # is UTF-8 source?
            # TODO: only support natural one line now
            if not handled and b'__pyarmor__(__name__, __file__,' in beacon:
                try:
                    with open(file_path, 'r') as f:
                        for line in f:
                            if line.startswith('__pyarmor__(') and line.rstrip().endswith(')'):
                                co = compile(line, '<str>', 'exec')
                                bytes_raw = co.co_consts[0]
                                assert type(bytes_raw) is bytes
                                assert bytes_raw.startswith(b'PY')
                                assert len(bytes_raw) > 64
                                break
                    logger.info(f'Found data in source: {relative_path}')
                    # FIXME: bytes_raw can be kept from last iteration
                    sequences.append((relative_path, bytes_raw))
                    del bytes_raw
                    handled = True
                except Exception as e:
                    logger.error(f'Assume source, but {e} ({file_path})')

            # TODO: is Nuitka package?
            # TODO: is pyc or single marshalled binary?

    # print(runtimes, [(i[0], i[1][:16]) for i in sequences], args.output_dir or args.directory)
    decrypt_process(runtimes, sequences, args.output_dir or args.directory)


if __name__ == '__main__':
    main()
