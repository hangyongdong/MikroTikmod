#!/usr/bin/env python3

import os
import sys
import shutil
import argparse
import subprocess
import tempfile
import re  # 🌟 新增：用于正则替换 ini 文件内容

from npk import NovaPackage, NpkPartID

VERSION = "1.3"  # 🌟 更新版本号

LICENSE_KEY = os.getenv('CUSTOM_LICENSE_PRIVATE_KEY')
SIGN_KEY = os.getenv('CUSTOM_NPK_SIGN_PRIVATE_KEY')

def run(cmd):
    print(">", cmd)
    process = subprocess.run(cmd, shell=True)
    if process.returncode != 0:
        print("Command failed")
        sys.exit(1)

def check_tools():
    tools = [
        "unsquashfs",
        "mksquashfs"
    ]
    for t in tools:
        if shutil.which(t) is None:
            print("Missing tool:", t)
            print("Install with:")
            print("sudo apt install squashfs-tools")
            sys.exit(1)

def copy_replace(src, dst):
    if not os.path.exists(dst):
        os.makedirs(dst)
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            copy_replace(s, d)
        else:
            shutil.copy2(s, d)
            print("Replace:", item)

def extract_squashfs(data, workdir):
    squashfs = os.path.join(workdir, "fs.sfs")
    with open(squashfs, "wb") as f:
        f.write(data)
    root = os.path.join(workdir, "root")
    run(f"unsquashfs -d {root} {squashfs}")
    return squashfs, root

def rebuild_squashfs(root, squashfs):
    if os.path.exists(squashfs):
        os.remove(squashfs)
    run(
        f"mksquashfs {root} {squashfs} "
        "-root-owned -Xbcj arm -comp xz -b 256k"
    )
    with open(squashfs, "rb") as f:
        return f.read()

def modify_global_ini(root_dir, max_vaps, low_mem):
    ini_path = os.path.join(root_dir, "lib", "config", "global.ini")
    
    if not os.path.exists(ini_path):
        print(f"  [!] Warning: {ini_path} not found. Skipping INI patch.")
        return

    with open(ini_path, 'r', encoding='utf-8') as f:
        content = f.read()

    changed = False

    if max_vaps is not None:
        content, n = re.subn(r'^max_vaps\s*=\s*\d+', f'max_vaps={max_vaps}', content, flags=re.MULTILINE)
        if n > 0:
            print(f"  [*] Patched max_vaps = {max_vaps}")
            changed = True
        else:
            print("  [!] max_vaps key not found in global.ini")

    if low_mem:
        content, n = re.subn(r'^low_mem_system\s*=\s*\d+', 'low_mem_system=1', content, flags=re.MULTILINE)
        if n > 0:
            print("  [*] Patched low_mem_system = 1")
            changed = True
        else:
            print("  [!] low_mem_system key not found in global.ini")

    if changed:
        with open(ini_path, 'w', encoding='utf-8') as f:
            f.write(content)

def patch_npk_multiple(input_npk, src_dirs, output_npks, target_path, max_vaps=None, low_mem=False):
    
    if not LICENSE_KEY or not SIGN_KEY:
        print("Error: Missing CUSTOM_LICENSE_PRIVATE_KEY or CUSTOM_NPK_SIGN_PRIVATE_KEY env variables.")
        sys.exit(1)

    print("[1/6] Loading Base NPK to extract filesystem")
    base_npk = NovaPackage.load(input_npk)
    pkg = base_npk[NpkPartID.NAME_INFO].data.name
    print("Package:", pkg)

    print("[2/6] Creating temp workspace")
    workdir = tempfile.mkdtemp(prefix="roswifi_")

    try:
        print("[3/6] Extracting base squashfs (Only done once for efficiency)")
        base_squashfs, base_root = extract_squashfs(
            base_npk[NpkPartID.SQUASHFS].data,
            workdir
        )

        if max_vaps is not None or low_mem:
            print("[3.5/6] Patching lib/config/global.ini")
            modify_global_ini(base_root, max_vaps, low_mem)

        for i, (s_dir, o_npk) in enumerate(zip(src_dirs, output_npks)):
            print(f"\n--- Processing Target {i+1}/{len(src_dirs)}: {o_npk} ---")
            
            current_root = os.path.join(workdir, f"root_mod_{i}")
            shutil.copytree(base_root, current_root)

            clean_target_path = target_path.lstrip("/")
            target = os.path.join(current_root, clean_target_path)
            
            print(f"[{i+1}-A] Replacing files from {s_dir} to NPK path: /{clean_target_path}")
            copy_replace(s_dir, target)

            print(f"[{i+1}-B] Rebuilding squashfs")
            new_squashfs_path = os.path.join(workdir, f"fs_mod_{i}.sfs")
            newfs = rebuild_squashfs(current_root, new_squashfs_path)

            print(f"[{i+1}-C] Injecting and Signing package")
            npk = NovaPackage.load(input_npk)
            npk[NpkPartID.SQUASHFS].data = newfs

            license_key = bytes.fromhex(LICENSE_KEY)
            sign_key = bytes.fromhex(SIGN_KEY)
            npk.sign(license_key, sign_key)

            npk.save(o_npk)
            print(f"[{i+1}-D] Successfully generated: {o_npk}")

    finally:
        print("\nCleaning workspace")
        shutil.rmtree(workdir)

def main():
    parser = argparse.ArgumentParser(
        prog="roswifi",
        description="RouterOS NPK files patch & resign tool (Multi-target Support)"
    )

    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Input base NPK"
    )

    parser.add_argument(
        "-b",
        "--bdwlan",
        "--src",
        dest="src_dirs",
        required=True,
        nargs='+',
        help="Source directories containing files to replace"
    )

    parser.add_argument(
        "-o",
        "--output",
        required=True,
        nargs='+',
        help="Output NPKs (must match the number of source directories)"
    )

    parser.add_argument(
        "-t",
        "--target",
        default="lib/bdwlan",
        help="Target directory path inside the NPK filesystem (default: lib/bdwlan)"
    )


    parser.add_argument(
        "--max-vaps",
        type=int,
        help="Change max_vaps value in lib/config/global.ini (e.g. --max-vaps 32)"
    )


    parser.add_argument(
        "--low-mem",
        action="store_true",
        help="Set low_mem_system=1 in lib/config/global.ini"
    )

    parser.add_argument(
        "--version",
        action="store_true"
    )

    args = parser.parse_args()

    if args.version:
        print("roswifi", VERSION)
        return

    check_tools()

    if not os.path.exists(args.input):
        print("Input NPK not found")
        sys.exit(1)

    if len(args.src_dirs) != len(args.output):
        print("Error: The number of source directories must match the number of output files.")
        sys.exit(1)

    for s_dir in args.src_dirs:
        if not os.path.exists(s_dir):
            print(f"Source directory not found: {s_dir}")
            sys.exit(1)

    # 🌟 传递新参数
    patch_npk_multiple(
        args.input,
        args.src_dirs,
        args.output,
        args.target,
        max_vaps=args.max_vaps,
        low_mem=args.low_mem
    )

if __name__ == "__main__":
    main()
