import argparse
from Crypto.Cipher import AES
import logging
import os
import asyncio
import traceback
import platform
import py_compile
import importlib.util
import struct
import marshal
import time
import sys
from typing import Dict, List, Tuple, Optional

try:
    from colorama import init, Fore, Style
except ImportError:
    def init(**kwargs): pass
    class Fore: CYAN = RED = YELLOW = GREEN = ''
    class Style: RESET_ALL = ''

from detect import detect_process
from runtime import RuntimeInfo


# Initialize colorama
init(autoreset=True)


def general_aes_ctr_decrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=2)
    return cipher.decrypt(data)


def bcc_fallback_method(seq_file_path: str, output_path: str = None):
    # Fallback method for BCC mode deobfuscation
    logger = logging.getLogger('shot')
    logger.info(f'{Fore.YELLOW}Attempting BCC fallback method for: {seq_file_path}{Style.RESET_ALL}')
    
    if output_path is None:
        output_path = seq_file_path + '.back.1shot.seq'
    
    try:
        with open(seq_file_path, 'rb') as f:
            origin = f.read()
        
        one_shot_header = origin[:32]   # Header format
        aes_key = one_shot_header[1:17]
        
        bcc_part_length = int.from_bytes(origin[0x58:0x5C], 'little')   # If it is 0, it is not BCC part but bytecode part
        bytecode_part = origin[32+bcc_part_length:]
        aes_nonce = bytecode_part[36:40] + bytecode_part[44:52]   # The same position as non-BCC file
        
        with open(output_path, 'wb') as f:
            f.write(one_shot_header)
            f.write(bytecode_part[:64])
            f.write(general_aes_ctr_decrypt(bytecode_part[64:], aes_key, aes_nonce))
        
        logger.info(f'{Fore.GREEN}Successfully created BCC fallback file: {output_path}{Style.RESET_ALL}')
        return output_path
    except Exception as e:
        error_details = traceback.format_exc()
        logger.error(f'{Fore.RED}BCC fallback method failed: {e}{Style.RESET_ALL}')
        logger.error(f'{Fore.RED}Error details: {error_details}{Style.RESET_ALL}')
        return None


async def run_subprocess_async(cmd, cwd=None):
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd
    )
    stdout, stderr = await process.communicate()
    return process.returncode, stdout, stderr


async def decrypt_file_async(exe_path, seq_file_path, path, args):
    logger = logging.getLogger('shot')
    try:
        # Run without timeout
        returncode, stdout, stderr = await run_subprocess_async([exe_path, seq_file_path])
        
        stdout_lines = stdout.decode('latin-1').splitlines()
        stderr_lines = stderr.decode('latin-1').splitlines()
        
        for line in stdout_lines:
            logger.warning(f'PYCDC: {line} ({path})')
        
        for line in stderr_lines:
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
            elif line.startswith((
                'Something TERRIBLE happened',
                'Unsupported argument',
                'Unsupported Node type',
                'Unsupported node type',
            )):  # annoying wont-fix errors
                if args.show_all:
                    logger.error(f'PYCDC: {line} ({path})')
            else:
                logger.error(f'PYCDC: {line} ({path})')
        
        return returncode, stdout_lines, stderr_lines
    except Exception as e:
        error_details = traceback.format_exc()
        logger.error(f'{Fore.RED}Error during async deobfuscation: {e}{Style.RESET_ALL}')
        logger.error(f'{Fore.RED}Error details: {error_details}{Style.RESET_ALL}')
        return -1, [], []


async def decrypt_process_async(runtimes: Dict[str, RuntimeInfo], sequences: List[Tuple[str, bytes]], args):
    logger = logging.getLogger('shot')
    output_dir: str = args.output_dir or args.directory
    
    # Create a semaphore to limit concurrent processes
    semaphore = asyncio.Semaphore(args.concurrent)  # Use the concurrent argument
    
    # Get the appropriate executable for the current platform
    exe_path = get_platform_executable(args)

    async def process_file(path, data):
        async with semaphore:
            try:
                serial_number = data[2:8].decode('utf-8')
                runtime = runtimes[serial_number]
                logger.info(f'{Fore.CYAN}Decrypting: {serial_number} ({path}){Style.RESET_ALL}')

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
                seq_file_path = dest_path + '.1shot.seq'
                with open(seq_file_path, 'wb') as f:
                    f.write(b'\xa1' + runtime.runtime_aes_key)
                    f.write(b'\xa2' + runtime.mix_str_aes_nonce())
                    f.write(b'\xf0\xff')
                    f.write(data[:cipher_text_offset])
                    f.write(general_aes_ctr_decrypt(
                        data[cipher_text_offset:cipher_text_offset+cipher_text_length], runtime.runtime_aes_key, nonce))
                    f.write(data[cipher_text_offset+cipher_text_length:])

                # Run without timeout
                returncode, stdout_lines, stderr_lines = await decrypt_file_async(exe_path, seq_file_path, path, args)
                
                # Check for specific errors that indicate BCC mode
                should_try_bcc = False
                error_message = ""

                # FIXME: Probably false positive
                if returncode != 0:
                    error_message = f"PYCDC returned {returncode}"
                    # Check for specific error patterns that suggest BCC mode
                    for line in stderr_lines:
                        if ("Unsupported opcode" in line or 
                            "Something TERRIBLE happened" in line or
                            "Unknown opcode 0" in line or
                            "Got unsupported type" in line):
                            should_try_bcc = True
                            error_message += f" - {line}"
                            break
                
                if should_try_bcc:
                    logger.warning(f'{Fore.YELLOW}{error_message} ({path}) - Attempting BCC fallback{Style.RESET_ALL}')
                    # Try BCC fallback method
                    bcc_file_path = bcc_fallback_method(seq_file_path)
                    if bcc_file_path:
                        logger.info(f'{Fore.GREEN}Running deobfuscator on BCC fallback file{Style.RESET_ALL}')
                        try:
                            # Run without timeout
                            returncode, stdout_lines, stderr_lines = await decrypt_file_async(exe_path, bcc_file_path, path, args)
                            if returncode == 0:
                                logger.info(f'{Fore.GREEN}Successfully deobfuscated using BCC fallback method{Style.RESET_ALL}')
                                print(f"{Fore.GREEN} BCC Decrypted: {path}{Style.RESET_ALL}")
                                
                                # Generate .pyc file if requested
                                if args.generate_pyc and path.endswith('.py'):
                                    py_file_path = dest_path
                                    pyc_file_path = py_file_path + 'c'  # .py -> .pyc
                                    generate_pyc_file(py_file_path, args.pyc_version, pyc_file_path)
                            else:
                                logger.error(f'{Fore.RED}BCC fallback deobfuscation failed with return code {returncode}{Style.RESET_ALL}')
                                for line in stderr_lines:
                                    logger.error(f'{Fore.RED}BCC Error: {line}{Style.RESET_ALL}')
                        except Exception as e:
                            error_details = traceback.format_exc()
                            logger.error(f'{Fore.RED}BCC fallback deobfuscation failed with error: {e}{Style.RESET_ALL}')
                            logger.error(f'{Fore.RED}Error details: {error_details}{Style.RESET_ALL}')
                elif returncode == 0:
                    # Successfully decrypted
                    logger.info(f'{Fore.GREEN}Successfully decrypted: {path}{Style.RESET_ALL}')
                    print(f"{Fore.GREEN} Decrypted: {path}{Style.RESET_ALL}")
                    
                    # Generate .pyc file if requested
                    if args.generate_pyc and path.endswith('.py'):
                        py_file_path = dest_path
                        pyc_file_path = py_file_path + 'c'  # .py -> .pyc
                        generate_pyc_file(py_file_path, args.pyc_version, pyc_file_path)
                else:
                    logger.warning(f'{Fore.YELLOW}{error_message} ({path}){Style.RESET_ALL}')
            except Exception as e:
                error_details = traceback.format_exc()
                logger.error(f'{Fore.RED}Decrypt failed: {e} ({path}){Style.RESET_ALL}')
                logger.error(f'{Fore.RED}Error details: {error_details}{Style.RESET_ALL}')
    
    # Create tasks for all files
    tasks = [process_file(path, data) for path, data in sequences]
    
    # Run all tasks concurrently
    await asyncio.gather(*tasks)


def decrypt_process(runtimes: Dict[str, RuntimeInfo], sequences: List[Tuple[str, bytes]], args):
    asyncio.run(decrypt_process_async(runtimes, sequences, args))


def get_platform_executable(args) -> str:
    """
    Get the appropriate executable for the current platform
    """
    logger = logging.getLogger('shot')

    # If a specific executable is provided, use it
    if args.executable:
        if os.path.exists(args.executable):
            logger.info(f'{Fore.GREEN}Using specified executable: {args.executable}{Style.RESET_ALL}')
            return args.executable
        else:
            logger.warning(f'{Fore.YELLOW}Specified executable not found: {args.executable}{Style.RESET_ALL}')

    helpers_dir = os.path.dirname(os.path.abspath(__file__))

    system = platform.system().lower()
    machine = platform.machine().lower()

    # Check for architecture-specific executables
    arch_specific_exe = f'pyarmor-1shot-{system}-{machine}'
    if system == 'windows':
        arch_specific_exe += '.exe'

    arch_exe_path = os.path.join(helpers_dir, arch_specific_exe)
    if os.path.exists(arch_exe_path):
        logger.info(f'{Fore.GREEN}Using architecture-specific executable: {arch_specific_exe}{Style.RESET_ALL}')
        return arch_exe_path

    platform_map = {
        'windows': 'pyarmor-1shot.exe',
        'linux': 'pyarmor-1shot',
        'darwin': 'pyarmor-1shot',
    }
    base_exe_name = platform_map.get(system, 'pyarmor-1shot')

    # Then check for platform-specific executable
    platform_exe_path = os.path.join(helpers_dir, base_exe_name)
    if os.path.exists(platform_exe_path):
        logger.info(f'{Fore.GREEN}Using platform-specific executable: {base_exe_name}{Style.RESET_ALL}')
        return platform_exe_path

    # Finally, check for generic executable
    generic_exe_path = os.path.join(helpers_dir, 'pyarmor-1shot')
    if os.path.exists(generic_exe_path):
        logger.info(f'{Fore.GREEN}Using generic executable: pyarmor-1shot{Style.RESET_ALL}')
        return generic_exe_path

    logger.critical(f'{Fore.RED}Executable {base_exe_name} not found, please build it first or download on https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot/releases {Style.RESET_ALL}')
    exit(1)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Pyarmor Static Unpack 1 Shot Entry')
    parser.add_argument(
        'directory',
        help='the "root" directory of obfuscated scripts',
        type=str,
        nargs='?',
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
    parser.add_argument(
        '--menu',
        help='show interactive menu to select folder to unpack',
        action='store_true',
    )
    parser.add_argument(
        '--concurrent',
        help='number of concurrent deobfuscation processes (default: 4)',
        type=int,
        default=4,
    )
    parser.add_argument(
        '-e',
        '--executable',
        help='path to the pyarmor-1shot executable to use',
        type=str,
    )
    parser.add_argument(
        '--generate-pyc',
        help='generate .pyc files after deobfuscation (for different Python versions)',
        action='store_true',
    )
    parser.add_argument(
        '--pyc-version',
        help='target Python version for generated .pyc files (e.g., 3.8, 3.9)',
        type=str,
        default=f"{sys.version_info.major}.{sys.version_info.minor}",
    )
    return parser.parse_args()


def display_menu():
    to_unpack_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'to_unpack')
    
    if not os.path.exists(to_unpack_dir):
        os.makedirs(to_unpack_dir)
       
    folders = [d for d in os.listdir(to_unpack_dir) 
               if os.path.isdir(os.path.join(to_unpack_dir, d))]
    
    if not folders:
        print(f"{Fore.YELLOW}No folders found in {to_unpack_dir}{Style.RESET_ALL}")
        return None
    
    print(f"\n{Fore.CYAN}=== Available Folders to Unpack ==={Style.RESET_ALL}")
    for i, folder in enumerate(folders, 1):
        print(f"{Fore.GREEN}[{i}]{Style.RESET_ALL} {folder}")
    
    while True:
        try:
            choice = input(f"\n{Fore.YELLOW}Enter the number of the folder to unpack (or 'q' to quit): {Style.RESET_ALL}")
            if choice.lower() == 'q':
                return None
            
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(folders):
                selected_folder = folders[choice_idx]
                full_path = os.path.join(to_unpack_dir, selected_folder)
                print(f"{Fore.GREEN}Selected: {selected_folder}{Style.RESET_ALL}")
                return full_path
            else:
                print(f"{Fore.RED}Invalid choice. Please enter a number between 1 and {len(folders)}{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Please enter a valid number{Style.RESET_ALL}")


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)-8s %(asctime)-28s %(message)s',
    )
    logger = logging.getLogger('shot')

    print(Fore.CYAN + r'''
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
''' + Style.RESET_ALL)

    # If menu option is selected or no directory is provided, show the menu
    if args.menu or not args.directory:
        selected_dir = display_menu()
        if selected_dir:
            args.directory = selected_dir
        else:
            print(f"{Fore.YELLOW}No directory selected. Exiting.{Style.RESET_ALL}")
            return

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
            logger.error(f'{Fore.RED}Please specify `pyarmor_runtime` file by `-r` if input is a file{Style.RESET_ALL}')
            return
        logger.info(f'{Fore.CYAN}Single file mode{Style.RESET_ALL}')
        result = detect_process(args.directory, args.directory)
        if result is None:
            logger.error(f'{Fore.RED}No armored data found{Style.RESET_ALL}')
            return
        sequences.extend(result)
        decrypt_process(runtimes, sequences, args)
        return  # single file mode ends here

    dir_path: str
    dirs: List[str]
    files: List[str]
    for dir_path, dirs, files in os.walk(args.directory, followlinks=False):
        if '.no1shot' in files:
            logger.info(f'{Fore.YELLOW}Skipping {dir_path} because of `.no1shot`{Style.RESET_ALL}')
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
                        f'{Fore.RED}A PYZ file containing armored data is detected, but the PYZ file has not been extracted by other tools. This error is not a problem with this tool. If the folder is extracted by Pyinstxtractor, please read the output information of Pyinstxtractor carefully. ({relative_path}){Style.RESET_ALL}')
                continue

            # is pyarmor_runtime?
            if specified_runtime is None \
                    and file_name.startswith('pyarmor_runtime') \
                    and file_name.endswith(('.pyd', '.so', '.dylib')):
                try:
                    new_runtime = RuntimeInfo(file_path)
                    runtimes[new_runtime.serial_number] = new_runtime
                    logger.info(
                        f'{Fore.GREEN}Found new runtime: {new_runtime.serial_number} ({file_path}){Style.RESET_ALL}')
                    print(new_runtime)
                    continue
                except:
                    pass

            result = detect_process(file_path, relative_path)
            if result is not None:
                sequences.extend(result)

    if not runtimes:
        logger.error(f'{Fore.RED}No runtime found{Style.RESET_ALL}')
        return
    if not sequences:
        logger.error(f'{Fore.RED}No armored data found{Style.RESET_ALL}')
        return

    if args.generate_pyc:
        logger.info(f'{Fore.CYAN}Pyc generation enabled for Python {args.pyc_version}{Style.RESET_ALL}')

    decrypt_process(runtimes, sequences, args)


# New function to generate pyc files
def generate_pyc_file(py_file_path: str, pyc_version: str, dest_path: Optional[str] = None) -> bool:
    """
    Generate a .pyc file from a .py file for a specific Python version.
    
    Args:
        py_file_path: Path to the .py file
        pyc_version: Target Python version (e.g., "3.8")
        dest_path: Optional destination path for the .pyc file
    
    Returns:
        bool: True if successful, False otherwise
    """
    logger = logging.getLogger('shot')
    
    try:
        if not os.path.exists(py_file_path):
            logger.error(f'{Fore.RED}Source file not found: {py_file_path}{Style.RESET_ALL}')
            return False
            
        # If no destination path provided, use source path with .pyc extension
        if dest_path is None:
            dest_path = py_file_path + '.pyc'
            
        # Parse target Python version
        try:
            major, minor = map(int, pyc_version.split('.'))
        except ValueError:
            logger.error(f'{Fore.RED}Invalid Python version format: {pyc_version}. Use format like "3.8"{Style.RESET_ALL}')
            return False
            
        # Current Python version
        current_major, current_minor = sys.version_info.major, sys.version_info.minor
        
        # If the target version is the same as current Python version, use py_compile
        if (major, minor) == (current_major, current_minor):
            logger.info(f'{Fore.CYAN}Generating .pyc file using current Python interpreter ({pyc_version}){Style.RESET_ALL}')
            try:
                py_compile.compile(py_file_path, dest_path, doraise=True)
                logger.info(f'{Fore.GREEN}Successfully generated .pyc file: {dest_path}{Style.RESET_ALL}')
                return True
            except Exception as e:
                logger.error(f'{Fore.RED}Failed to compile with py_compile: {e}{Style.RESET_ALL}')
                return False
                
        # If target version is different, manually create the .pyc file
        logger.info(f'{Fore.CYAN}Generating .pyc file for Python {pyc_version}{Style.RESET_ALL}')
        
        # Define magic numbers for different Python versions
        magic_numbers = {
            (3, 7): 3394,
            (3, 8): 3413,
            (3, 9): 3425,
            (3, 10): 3439,
            (3, 11): 3495,
            (3, 12): 3531,
        }
        
        # Check if the target version is supported
        if (major, minor) not in magic_numbers:
            logger.error(f'{Fore.RED}Unsupported Python version: {pyc_version}. Supported versions: {", ".join([f"{maj}.{min}" for maj, min in magic_numbers.keys()])}{Style.RESET_ALL}')
            return False
            
        # Get the magic number for the target version
        magic = magic_numbers[(major, minor)]
        
        # Compile the source code
        with open(py_file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
            
        try:
            code_object = compile(source_code, py_file_path, 'exec')
        except Exception as e:
            logger.error(f'{Fore.RED}Failed to compile source code: {e}{Style.RESET_ALL}')
            return False
            
        # Create the pyc file
        with open(dest_path, 'wb') as pyc_file:
            # Write magic number
            pyc_file.write(struct.pack('<H', magic))
            pyc_file.write(b'\r\n')
            
            # Write timestamp (32-bit)
            timestamp = int(os.path.getmtime(py_file_path))
            pyc_file.write(struct.pack('<I', timestamp))
            
            # Write size parameter for Python 3.7+
            size = os.path.getsize(py_file_path)
            pyc_file.write(struct.pack('<I', size))
            
            # Write the code object
            marshal.dump(code_object, pyc_file)
            
        logger.info(f'{Fore.GREEN}Successfully generated .pyc file for Python {pyc_version}: {dest_path}{Style.RESET_ALL}')
        return True
    
    except Exception as e:
        error_details = traceback.format_exc()
        logger.error(f'{Fore.RED}Failed to generate .pyc file: {e}{Style.RESET_ALL}')
        logger.error(f'{Fore.RED}Error details: {error_details}{Style.RESET_ALL}')
        return False


if __name__ == '__main__':
    main()
