import argparse
from Crypto.Cipher import AES
import logging
import os
import asyncio
import traceback
import platform
import locale
from typing import Dict, List, Tuple

try:
    from colorama import init, Fore, Style  # type: ignore
except ImportError:

    def init(**kwargs):
        pass

    class Fore:
        CYAN = RED = YELLOW = GREEN = ""

    class Style:
        RESET_ALL = ""


from detect import detect_process
from runtime import RuntimeInfo
from util import dword, bytes_sub


# Initialize colorama
init(autoreset=True)


def general_aes_ctr_decrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=2)
    return cipher.decrypt(data)


def decode_output(data: bytes) -> str:
    if not data:
        return ""

    # 1) try chardet if available to guess encoding
    try:
        import chardet  # type: ignore

        res = chardet.detect(data)
        enc = res.get("encoding")
        if enc:
            return data.decode(enc, errors="replace")
    except Exception:
        pass

    # 2) try common encodings in a reasonable order
    attempts = [
        "utf-8",
        "utf-8-sig",
        locale.getpreferredencoding(False) or None,
        "cp936",
        "latin-1",
    ]
    for enc in attempts:
        if not enc:
            continue
        try:
            return data.decode(enc)
        except Exception:
            continue

    try:
        return data.decode("latin-1", errors="replace")
    except Exception:
        return ""


async def run_pycdc_async(
    exe_path: str,
    seq_file_path: str,
    path_for_log: str,
    *,
    unit_buf: bool = False,
    no_banner: bool = False,
    show_all: bool = False,
    show_err_opcode: bool = False,
    show_warn_stack: bool = False,
):
    logger = logging.getLogger("shot")
    try:
        options = []
        if unit_buf:
            options.append("--unitbuf")
        if no_banner:
            options.append("--no-banner")
        process = await asyncio.create_subprocess_exec(
            exe_path,
            *options,
            seq_file_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        stdout_lines = decode_output(stdout).splitlines()
        stderr_lines = decode_output(stderr).splitlines()

        for line in stdout_lines:
            logger.warning(f"PYCDC: {line} ({path_for_log})")

        for line in stderr_lines:
            if not unit_buf and line.startswith("Access violation caught"):
                # retry with --unitbuf
                await run_pycdc_async(
                    exe_path,
                    seq_file_path,
                    path_for_log,
                    unit_buf=True,
                    no_banner=no_banner,
                    show_all=show_all,
                    show_err_opcode=show_err_opcode,
                    show_warn_stack=show_warn_stack,
                )
                # do not log anything because it will be logged in the retried call
                return

            if line.startswith(
                (
                    "Warning: Stack history is empty",
                    "Warning: Stack history is not empty",
                    "Warning: block stack is not empty",
                )
            ):
                if show_warn_stack or show_all:
                    logger.warning(f"PYCDC: {line} ({path_for_log})")
            elif line.startswith("Unsupported opcode:"):
                if show_err_opcode or show_all:
                    logger.error(f"PYCDC: {line} ({path_for_log})")
            elif line.startswith(
                (
                    "Something TERRIBLE happened",
                    "Unsupported argument",
                    "Unsupported Node type",
                    "Unsupported node type",
                    "Access violation caught",
                )
            ):  # annoying wont-fix errors
                if show_all:
                    logger.error(f"PYCDC: {line} ({path_for_log})")
            else:
                logger.error(f"PYCDC: {line} ({path_for_log})")

        if process.returncode != 0:
            logger.warning(
                f"{Fore.YELLOW}PYCDC returned 0x{process.returncode:x} ({path_for_log}){Style.RESET_ALL}"
            )

    except Exception as e:
        error_details = traceback.format_exc()
        logger.error(f"{Fore.RED}Exception: {e} ({path_for_log}){Style.RESET_ALL}")
        logger.error(f"{Fore.RED}Error details: {error_details}{Style.RESET_ALL}")


async def decrypt_process_async(
    runtimes: Dict[str, RuntimeInfo], sequences: List[Tuple[str, bytes]], args
):
    logger = logging.getLogger("shot")
    output_dir: str = args.output_dir or args.directory
    exe_path = get_platform_executable(args.executable)
    semaphore = asyncio.Semaphore(args.concurrent)

    async def process_file(relative_path, data):
        async with semaphore:
            try:
                serial_number = data[2:8].decode("utf-8", errors="replace")
                runtime = runtimes[serial_number]
                logger.info(
                    f"{Fore.CYAN}Decrypting: {serial_number} ({relative_path}){Style.RESET_ALL}"
                )

                dest_path = (
                    os.path.join(output_dir, relative_path)
                    if output_dir
                    else os.path.abspath(relative_path)  # resolve with working dir
                )  # abs or rel, must has a dirname, must not ends with slash
                dest_dir = os.path.dirname(dest_path)
                if not os.path.exists(dest_dir):
                    os.makedirs(dest_dir)

                if args.export_raw_data:
                    with open(dest_path + ".1shot.raw", "wb") as f:
                        f.write(data)

                # Check BCC; mutates "data"
                if dword(data, 20) == 9:
                    cipher_text_offset = dword(data, 28)
                    cipher_text_length = dword(data, 32)
                    nonce = data[36:40] + data[44:52]
                    bcc_aes_decrypted = general_aes_ctr_decrypt(
                        bytes_sub(data, cipher_text_offset, cipher_text_length),
                        runtime.runtime_aes_key,
                        nonce,
                    )
                    data = data[dword(data, 56) :]
                    bcc_architecture_mapping = {
                        0x2001: "win-x64",
                        0x2003: "linux-x64",
                    }
                    while True:
                        if len(bcc_aes_decrypted) < 16:
                            break
                        bcc_segment_offset = dword(bcc_aes_decrypted, 0)
                        bcc_segment_length = dword(bcc_aes_decrypted, 4)
                        bcc_architecture_id = dword(bcc_aes_decrypted, 8)
                        bcc_next_segment_offset = dword(bcc_aes_decrypted, 12)
                        bcc_architecture = bcc_architecture_mapping.get(
                            bcc_architecture_id, f"0x{bcc_architecture_id:x}"
                        )
                        bcc_file_path = f"{dest_path}.1shot.bcc.{bcc_architecture}.so"
                        with open(bcc_file_path, "wb") as f:
                            f.write(
                                bytes_sub(
                                    bcc_aes_decrypted,
                                    bcc_segment_offset,
                                    bcc_segment_length,
                                )
                            )
                        logger.info(
                            f"{Fore.GREEN}Extracted BCC mode native part: {bcc_file_path}{Style.RESET_ALL}"
                        )
                        if bcc_next_segment_offset == 0:
                            break
                        bcc_aes_decrypted = bcc_aes_decrypted[bcc_next_segment_offset:]

                cipher_text_offset = dword(data, 28)
                cipher_text_length = dword(data, 32)
                nonce = data[36:40] + data[44:52]
                seq_file_path = dest_path + ".1shot.seq"
                with open(seq_file_path, "wb") as f:
                    f.write(b"\xa1" + runtime.runtime_aes_key)
                    f.write(b"\xa2" + runtime.mix_str_aes_nonce())
                    f.write(b"\xf0\xff")
                    f.write(data[:cipher_text_offset])
                    f.write(
                        general_aes_ctr_decrypt(
                            bytes_sub(data, cipher_text_offset, cipher_text_length),
                            runtime.runtime_aes_key,
                            nonce,
                        )
                    )
                    f.write(data[cipher_text_offset + cipher_text_length :])

                await run_pycdc_async(
                    exe_path,
                    seq_file_path,
                    relative_path,
                    no_banner=args.no_banner,
                    show_all=args.show_all,
                    show_err_opcode=args.show_err_opcode,
                    show_warn_stack=args.show_warn_stack,
                )

            except Exception as e:
                error_details = traceback.format_exc()
                logger.error(
                    f"{Fore.RED}Decrypt failed: {e} ({relative_path}){Style.RESET_ALL}"
                )
                logger.error(
                    f"{Fore.RED}Error details: {error_details}{Style.RESET_ALL}"
                )

    tasks = [process_file(path, data) for path, data in sequences]
    await asyncio.gather(*tasks)


def decrypt_process(
    runtimes: Dict[str, RuntimeInfo], sequences: List[Tuple[str, bytes]], args
):
    asyncio.run(decrypt_process_async(runtimes, sequences, args))


def get_platform_executable(specified: str) -> str:
    logger = logging.getLogger("shot")

    # If a specific executable is provided, use it
    if specified:
        if os.path.exists(specified):
            logger.info(
                f"{Fore.GREEN}Using specified executable: {specified}{Style.RESET_ALL}"
            )
            return specified
        else:
            logger.warning(
                f"{Fore.YELLOW}Specified executable not found: {specified}{Style.RESET_ALL}"
            )

    oneshot_dir = os.path.dirname(os.path.abspath(__file__))

    system = platform.system().lower()
    machine = platform.machine().lower()

    # Check for architecture-specific executables
    arch_specific_exe = f"pyarmor-1shot-{system}-{machine}"
    if system == "windows":
        arch_specific_exe += ".exe"

    arch_exe_path = os.path.join(oneshot_dir, arch_specific_exe)
    if os.path.exists(arch_exe_path):
        logger.info(
            f"{Fore.GREEN}Using architecture-specific executable: {arch_specific_exe}{Style.RESET_ALL}"
        )
        return arch_exe_path

    # Allow ".elf" and ".macho" suffixes, so that they can exist in the same folder
    platform_map = {
        "windows": ["pyarmor-1shot.exe", "pyarmor-1shot"],
        "linux": ["pyarmor-1shot", "pyarmor-1shot.elf"],
        "darwin": ["pyarmor-1shot", "pyarmor-1shot.macho"],
    }

    # Then check for platform-specific executable
    for base_exe_name in platform_map.get(system, ["pyarmor-1shot"]):
        platform_exe_path = os.path.join(oneshot_dir, base_exe_name)
        if os.path.exists(platform_exe_path):
            logger.info(
                f"{Fore.GREEN}Using executable: {base_exe_name}{Style.RESET_ALL}"
            )
            return platform_exe_path

    platform_default = platform_map.get(system, ["pyarmor-1shot"])[0]
    logger.critical(
        f"{Fore.RED}Executable {platform_default} not found, please build it first or download on https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot/releases {Style.RESET_ALL}"
    )
    exit(1)


def parse_args():
    parser = argparse.ArgumentParser(description="Pyarmor Static Unpack 1 Shot Entry")
    parser.add_argument(
        "directory",
        help='the "root" directory of obfuscated scripts',
        type=str,
    )
    parser.add_argument(
        "-r",
        "--runtime",
        help="path to pyarmor_runtime[.pyd|.so|.dylib]",
        type=str,  # argparse.FileType('rb'),
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        help="save output files in another directory instead of in-place, with folder structure remain unchanged",
        type=str,
    )
    parser.add_argument(
        "--export-raw-data",
        help="save data found in source files as-is",
        action="store_true",
    )
    parser.add_argument(
        "--show-all",
        help="show all pycdc errors and warnings",
        action="store_true",
    )
    parser.add_argument(
        "--show-err-opcode",
        help="show pycdc unsupported opcode errors",
        action="store_true",
    )
    parser.add_argument(
        "--show-warn-stack",
        help="show pycdc stack related warnings",
        action="store_true",
    )
    parser.add_argument(
        "--concurrent",
        help="number of concurrent handling processes (default: 4)",
        type=int,
        default=4,
    )
    parser.add_argument(
        "-e",
        "--executable",
        help="path to the pyarmor-1shot executable to use",
        type=str,
    )
    parser.add_argument(
        "--no-banner",
        help="do not show banner in console and output files",
        action="store_true",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)-8s %(asctime)-28s %(message)s",
    )
    logger = logging.getLogger("shot")

    if not args.no_banner:
        print(rf"""{Fore.CYAN}
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
(____)                                                        v0.2.2     (____)

              For technology exchange only. Use at your own risk.
        GitHub: https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot
{Style.RESET_ALL}""")

    if args.runtime:
        specified_runtime = RuntimeInfo(args.runtime)
        print(specified_runtime)
        runtimes = {specified_runtime.serial_number: specified_runtime}
    else:
        specified_runtime = None
        runtimes = {"000000": RuntimeInfo.default()}

    if args.output_dir and not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    if args.output_dir and not os.path.isdir(args.output_dir):
        logger.error(
            f"{Fore.RED}Cannot use {repr(args.output_dir)} as output directory{Style.RESET_ALL}"
        )
        return

    # Note for path handling:
    # args.output_dir: is either None or an existing directory path, can be absolute or relative
    # args.directory: before calling `decrypt_process`, it is an existing directory path, can be absolute or relative
    # paths in `sequences`: must be relative file paths, without trailing slashes, can exist or not

    if os.path.isfile(args.directory):
        single_file_path = os.path.abspath(args.directory)
        args.directory = os.path.dirname(single_file_path)
        relative_path = os.path.basename(single_file_path)
        if specified_runtime is None:
            logger.error(
                f"{Fore.RED}Please specify `pyarmor_runtime` file by `-r` if input is a file{Style.RESET_ALL}"
            )
            return
        logger.info(f"{Fore.CYAN}Single file mode{Style.RESET_ALL}")
        single_file_sequences = detect_process(single_file_path, relative_path)
        if single_file_sequences is None:
            logger.error(f"{Fore.RED}No armored data found{Style.RESET_ALL}")
            return
        decrypt_process(runtimes, single_file_sequences, args)
        return  # single file mode ends here

    sequences: List[Tuple[str, bytes]] = []

    dir_path: str
    dirs: List[str]
    files: List[str]
    for dir_path, dirs, files in os.walk(args.directory, followlinks=False):
        if ".no1shot" in files:
            logger.info(
                f"{Fore.YELLOW}Skipping {dir_path} because of `.no1shot`{Style.RESET_ALL}"
            )
            dirs.clear()
            files.clear()
            continue
        for d in ["__pycache__", "site-packages"]:
            if d in dirs:
                dirs.remove(d)
        for file_name in files:
            if ".1shot." in file_name:
                continue

            file_path = os.path.join(dir_path, file_name)
            relative_path = os.path.relpath(file_path, args.directory)

            if file_name.endswith(".pyz"):
                with open(file_path, "rb") as f:
                    head = f.read(16 * 1024 * 1024)
                if b"PY00" in head and (
                    not os.path.exists(file_path + "_extracted")
                    or len(os.listdir(file_path + "_extracted")) == 0
                ):
                    logger.error(
                        f"{Fore.RED}A PYZ file containing armored data is detected, but the PYZ file has not been extracted by other tools. This error is not a problem with this tool. If the folder is extracted by Pyinstxtractor, please read the output information of Pyinstxtractor carefully. ({relative_path}){Style.RESET_ALL}"
                    )
                continue

            # is pyarmor_runtime?
            if (
                specified_runtime is None
                and file_name.startswith("pyarmor_runtime")
                and file_name.endswith((".pyd", ".so", ".dylib"))
            ):
                try:
                    new_runtime = RuntimeInfo(file_path)
                    runtimes[new_runtime.serial_number] = new_runtime
                    logger.info(
                        f"{Fore.GREEN}Found new runtime: {new_runtime.serial_number} ({file_path}){Style.RESET_ALL}"
                    )
                    print(new_runtime)
                    continue
                except Exception:
                    pass

            result = detect_process(file_path, relative_path)
            if result is not None:
                sequences.extend(result)

    if not runtimes:
        logger.error(f"{Fore.RED}No `pyarmor_runtime` file found{Style.RESET_ALL}")
        return
    if not sequences:
        logger.error(f"{Fore.RED}No armored data found{Style.RESET_ALL}")
        return
    decrypt_process(runtimes, sequences, args)


if __name__ == "__main__":
    main()
