import subprocess,lzma
import struct,os,re,sys,tempfile
import shutil
try:
    import pefile
except ImportError:
    pefile = None

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    ELFFile = None
from npk import NovaPackage,NpkPartID,NpkFileContainer

def replace_chunks(old_chunks,new_chunks,data,name):
    pattern_parts = [re.escape(chunk) + b'(.{0,6})' for chunk in old_chunks[:-1]]
    pattern_parts.append(re.escape(old_chunks[-1])) 
    pattern_bytes = b''.join(pattern_parts)
    pattern = re.compile(pattern_bytes, flags=re.DOTALL) 
    def replace_match(match):
        replaced = b''.join([new_chunks[i] + match.group(i+1) for i in range(len(new_chunks) - 1)])
        replaced += new_chunks[-1]
        print(f'{name} public key patched {b"".join(old_chunks)[:16].hex().upper()}...')
        return replaced
    return re.sub(pattern, replace_match, data)

def replace_key(old,new,data,name=''):
    def generate_arm32_load_r3(chunk_bytes):
        """动态生成装载 32 位常数到 R3 寄存器的 ARM 指令"""
        val = struct.unpack('<I', chunk_bytes)[0]
        lower_16 = val & 0xFFFF
        upper_16 = (val >> 16) & 0xFFFF
        
        # MOVW r3, #lower_16 (Opcode: E3003000)
        imm4_l = (lower_16 >> 12) & 0xF
        imm12_l = lower_16 & 0xFFF
        instr1 = 0xE3003000 | (imm4_l << 16) | imm12_l
        
        # MOVT r3, #upper_16 (Opcode: E3403000)
        imm4_u = (upper_16 >> 12) & 0xF
        imm12_u = upper_16 & 0xFFF
        instr2 = 0xE3403000 | (imm4_u << 16) | imm12_u
        
        # NOP (MOV r0, r0) 补齐第三条指令位置
        instr3 = 0xE1A00000
        
        return [
            struct.pack('<I', instr1),
            struct.pack('<I', instr2),
            struct.pack('<I', instr3)
        ]
    old_chunks = [old[i:i+4] for i in range(0, len(old), 4)]
    new_chunks = [new[i:i+4] for i in range(0, len(new), 4)]
    data =  replace_chunks(old_chunks, new_chunks, data,name)
    key_map = [28,19,25,16,14,3,24,15,22,8,6,17,11,7,9,23,18,13,10,0,26,21,2,5,20,30,31,4,27,29,1,12,]
    old_chunks = [bytes([old[i]]) for i in key_map]
    new_chunks = [bytes([new[i]]) for i in key_map]
    data =  replace_chunks(old_chunks, new_chunks, data,name)
    arch = os.getenv('ARCH') or 'x86'
    arch = arch.replace('-', '')
    if arch in ['arm64','arm']:
        old_chunks = [old[i:i+4] for i in range(0, len(old), 4)]
        new_chunks = [new[i:i+4] for i in range(0, len(new), 4)]
        old_bytes = old_chunks[4] + old_chunks[5] + old_chunks[2] + old_chunks[0] + old_chunks[1] + old_chunks[6] + old_chunks[7]
        new_bytes = new_chunks[4] + new_chunks[5] + new_chunks[2] + new_chunks[0] + new_chunks[1] + new_chunks[6] + new_chunks[7]
        if old_bytes in data:
            print(f'{name} public key patched {old[:16].hex().upper()}...')
            data = data.replace(old_bytes,new_bytes)
            old_codes = [bytes.fromhex('793583E2'),bytes.fromhex('FD3A83E2'),bytes.fromhex('193D83E2')]  #0x1e400000+0xfd000+0x640
            new_codes = generate_arm32_load_r3(new_chunks[3])
            #new_codes = [bytes.fromhex('FF34A0E3'),bytes.fromhex('753C83E2'),bytes.fromhex('FC3083E2')]
            data =  replace_chunks(old_codes, new_codes, data,name)
        else:
            def conver_chunks(data:bytes):
                ret = [
                    (data[2] << 16) | (data[1] << 8) | data[0] | ((data[3] << 24) & 0x03000000),
                    (data[3] >> 2) | (data[4] << 6) | (data[5] << 14) | ((data[6] << 22) & 0x1C00000),
                    (data[6] >> 3) | (data[7] << 5) | (data[8] << 13) | ((data[9] << 21) & 0x3E00000),
                    (data[9] >> 5) | (data[10] << 3) | (data[11] << 11) | ((data[12] << 19) & 0x1F80000),
                    (data[12] >> 6) | (data[13] << 2) | (data[14] << 10) | (data[15] << 18),
                    data[16] | (data[17] << 8) | (data[18] << 16) | ((data[19] << 24) & 0x01000000),
                    (data[19] >> 1) | (data[20] << 7) | (data[21] << 15) | ((data[22] << 23) & 0x03800000),
                    (data[22] >> 3) | (data[23] << 5) | (data[24] << 13) | ((data[25] << 21) & 0x1E00000),
                    (data[25] >> 4) | (data[26] << 4) | (data[27] << 12) | ((data[28] << 20) & 0x3F00000),
                    (data[28] >> 6) | (data[29] << 2) | (data[30] << 10) | (data[31] << 18)
                ]
                return [struct.pack('<I', x ) for x in ret]
            old_chunks = conver_chunks(old)
            new_chunks = conver_chunks(new)
            old_bytes = b''.join([v for i,v in enumerate(old_chunks) if i != 8])
            new_bytes = b''.join([v for i,v in enumerate(new_chunks) if i != 8])
            if old_bytes in data:
                print(f'{name} public key patched {old[:16].hex().upper()}...')
                data = data.replace(old_bytes,new_bytes)
                old_codes = [bytes.fromhex('713783E2'),bytes.fromhex('223A83E2'),bytes.fromhex('8D3F83E2')]  #0x1C40000+0x22000+0x234
                new_codes = generate_arm32_load_r3(new_chunks[8])
                #new_codes = [bytes.fromhex('973303E3'),bytes.fromhex('DD3883E3'),bytes.fromhex('033483E3')]  0x03DD3397 = 0x3397|0x00DD0000|0x03000000
                data =  replace_chunks(old_codes, new_codes, data,name)

    return data

def patch_bzimage(data:bytes,key_dict:dict):
    PE_TEXT_SECTION_OFFSET = 414
    HEADER_PAYLOAD_OFFSET = 584
    HEADER_PAYLOAD_LENGTH_OFFSET = HEADER_PAYLOAD_OFFSET + 4
    text_section_raw_data = struct.unpack_from('<I',data,PE_TEXT_SECTION_OFFSET)[0]
    payload_offset =  text_section_raw_data +struct.unpack_from('<I',data,HEADER_PAYLOAD_OFFSET)[0]
    payload_length_orig = struct.unpack_from('<I',data,HEADER_PAYLOAD_LENGTH_OFFSET)[0]
    payload_length_actual = payload_length_orig - 4 #last 4 bytes is uncompressed size(z_output_len)
    z_output_len = struct.unpack_from('<I',data,payload_offset+payload_length_actual)[0]
    vmlinux_xz = data[payload_offset:payload_offset+payload_length_actual]
    vmlinux = lzma.decompress(vmlinux_xz)
    assert z_output_len == len(vmlinux), 'vmlinux size is not equal to expected'
    CPIO_HEADER_MAGIC = b'07070100'
    CPIO_FOOTER_MAGIC = b'TRAILER!!!\x00\x00\x00\x00' #545241494C455221212100000000
    cpio_offset1 = vmlinux.index(CPIO_HEADER_MAGIC)
    initramfs = vmlinux[cpio_offset1:]
    cpio_offset2 = initramfs.index(CPIO_FOOTER_MAGIC)+len(CPIO_FOOTER_MAGIC)
    initramfs = initramfs[:cpio_offset2]
    new_initramfs = initramfs       
    for old_public_key,new_public_key in key_dict.items():
        new_initramfs = replace_key(old_public_key,new_public_key,new_initramfs,'initramfs')
    new_vmlinux = vmlinux.replace(initramfs,new_initramfs)
    new_vmlinux_xz = lzma.compress(new_vmlinux,check=lzma.CHECK_CRC32,filters=[
            {"id": lzma.FILTER_X86},
            {"id": lzma.FILTER_LZMA2, 
             "preset": 9 | lzma.PRESET_EXTREME,
             'dict_size': 32*1024*1024,
              "lc": 4,"lp": 0, "pb": 0,
             },
        ])
    new_payload_length_actual = len(new_vmlinux_xz)
    assert new_payload_length_actual <= payload_length_actual , 'new vmlinux.xz size is too big'
    new_payload_length_header = new_payload_length_actual + 4 #last 4 bytes is uncompressed size(z_output_len)
    new_data = bytearray(data)
    struct.pack_into('<I',new_data,HEADER_PAYLOAD_LENGTH_OFFSET,new_payload_length_header)

    # Place new compressed payload and pad with zero bytes up to old total length
    old_full_len = payload_length_actual + 4
    new_full = new_vmlinux_xz + struct.pack('<I', len(new_vmlinux))
    new_full = new_full.ljust(old_full_len, b'\0')
    new_data[payload_offset : payload_offset + old_full_len] = new_full

    # Search and patch decompressor code instructions located after the payload
    payload_end = payload_offset + old_full_len
    decompressor_code = bytes(new_data[payload_end:])

    # Patch decompressor hardcoded input_len immediate (mov $payload_length, %ecx)
    pat_header = b'\xb9' + struct.pack('<I', payload_length_orig)
    pat_actual = b'\xb9' + struct.pack('<I', payload_length_actual)
    m_header = re.search(re.escape(pat_header), decompressor_code)
    if m_header:
        struct.pack_into('<I', new_data, payload_end + m_header.start() + 1, new_payload_length_header)
    m_actual = re.search(re.escape(pat_actual), decompressor_code)
    if m_actual:
        struct.pack_into('<I', new_data, payload_end + m_actual.start() + 1, new_payload_length_actual)

    # Patch decompressor hardcoded output_len immediate (mov $z_output_len, %r9) if present
    pat_out = b'\x49\xc7\xc1' + struct.pack('<I', z_output_len)
    m_out = re.search(re.escape(pat_out), decompressor_code)
    if m_out:
        struct.pack_into('<I', new_data, payload_end + m_out.start() + 3, len(new_vmlinux))

    # Maintain z_output_len at the fixed .rodata symbol address at payload end
    struct.pack_into('<I', new_data, payload_offset + payload_length_actual, len(new_vmlinux))
    return new_data

def patch_block(dev:str,file:str,key_dict):
    BLOCK_SIZE = 4096
    #sudo debugfs /dev/nbd0p1 -R 'stats' | grep "Block size" | sed -n '1p' | cut -d ':' -f 2 

    #sudo debugfs /dev/nbd0p1 -R 'stat boot/initrd.rgz' 2> /dev/null | sed -n '11p'
    stdout,_ = run_shell_command(f"debugfs {dev} -R 'stat {file}' 2> /dev/null | sed -n '11p' ")
    #(0-11):1592-1603, (IND):1173, (12-15):1604-1607, (16-26):1424-1434
    blocks_info = stdout.decode().strip().split(',')
    print(f'blocks_info : {blocks_info}')
    blocks = []
    ind_block_id = None
    for block_info in blocks_info:
        _tmp = block_info.strip().split(':')
        if _tmp[0].strip() == '(IND)':
            ind_block_id =  int(_tmp[1])
        else:
            print(f'block_info : {block_info}')
            id_range = _tmp[0].strip().replace('(','').replace(')','').split('-')
            block_range = _tmp[1].strip().replace('(','').replace(')','').split('-')
            blocks += [id for id in range(int(block_range[0]),int(block_range[1])+1)]
    print(f' blocks : {len(blocks)} ind_block_id : {ind_block_id}')
    
    #sudo debugfs /dev/nbd0p1  -R 'cat boot/initrd.rgz' > data
    data,stderr = run_shell_command(f"debugfs {dev} -R 'cat {file}' 2> /dev/null")
    new_data = patch_kernel(data,key_dict)
    print(f'write block {len(blocks)} : [',end="")
    with open(dev,'wb') as f:
        for index,block_id in enumerate(blocks):
            print('#',end="")
            f.seek(block_id*BLOCK_SIZE)
            f.write(new_data[index*BLOCK_SIZE:(index+1)*BLOCK_SIZE])
        f.flush()
        print(']')
        
def patch_initrd_xz(initrd_xz:bytes,key_dict:dict,ljust=True):
    try:
        initrd = lzma.decompress(initrd_xz)
    except Exception as e:
        print(f'size:{len(initrd_xz)},header:{initrd_xz[:20].hex().upper()},footer:{initrd_xz[-20:].hex().upper()}\n')
        raise Exception(f'failed to decompress initrd_xz: {e}')
    new_initrd = initrd  
    for old_public_key,new_public_key in key_dict.items():
        new_initrd = replace_key(old_public_key,new_public_key,new_initrd,'initrd')
    preset = 6
    new_initrd_xz = lzma.compress(new_initrd,check=lzma.CHECK_CRC32,filters=[{"id": lzma.FILTER_LZMA2, "preset": preset }] )
    while len(new_initrd_xz) > len(initrd_xz) and preset < 9:
        print(f'preset:{preset}')
        print(f'new initrd xz size:{len(new_initrd_xz)}')
        print(f'old initrd xz size:{len(initrd_xz)}')
        preset += 1
        new_initrd_xz = lzma.compress(new_initrd,check=lzma.CHECK_CRC32,filters=[{"id": lzma.FILTER_LZMA2, "preset": preset }] )
    if len(new_initrd_xz) > len(initrd_xz):
        new_initrd_xz = lzma.compress(new_initrd,check=lzma.CHECK_CRC32,filters=[{"id": lzma.FILTER_LZMA2, "preset": 9 | lzma.PRESET_EXTREME,'dict_size': 32*1024*1024,"lc": 4,"lp": 0, "pb": 0,}] )
    if ljust:
        print(f'preset:{preset}')
        print(f'new initrd xz size:{len(new_initrd_xz)}')
        print(f'old initrd xz size:{len(initrd_xz)}')
        print(f'ljust size:{len(initrd_xz)-len(new_initrd_xz)}')
        assert len(new_initrd_xz) <= len(initrd_xz),'new initrd xz size is too big'
        new_initrd_xz = new_initrd_xz.ljust(len(initrd_xz),b'\0')
    return new_initrd_xz

def find_7zXZ_data(data:bytes):
    offset1 = 0
    _data = data
    while b'\xFD7zXZ\x00\x00\x01' in _data:
        offset1 = offset1 + _data.index(b'\xFD7zXZ\x00\x00\x01') + 8
        _data = _data[offset1:]
    offset1 -= 8
    offset2 = 0
    _data = data
    while b'\x00\x00\x00\x00\x01\x59\x5A' in _data:
        offset2 = offset2 + _data.index(b'\x00\x00\x00\x00\x01\x59\x5A') + 7
        _data = _data[offset2:]
    print(f'found 7zXZ data offset:{offset1} size:{offset2-offset1}')
    return data[offset1:offset2] 

def patch_elf(data: bytes,key_dict:dict):
    initrd_xz = find_7zXZ_data(data)
    new_initrd_xz =  patch_initrd_xz(initrd_xz,key_dict)
    return data.replace(initrd_xz,new_initrd_xz)

def patch_pe(data: bytes,key_dict:dict):
    vmlinux_xz = find_7zXZ_data(data)
    vmlinux = lzma.decompress(vmlinux_xz)
    initrd_xz_offset = vmlinux.index(b'\xFD7zXZ\x00\x00\x01')
    initrd_xz_size = vmlinux[initrd_xz_offset:].index(b'\x00\x00\x00\x00\x01\x59\x5A') + 7
    initrd_xz = vmlinux[initrd_xz_offset:initrd_xz_offset+initrd_xz_size]
    new_initrd_xz = patch_initrd_xz(initrd_xz,key_dict)  
    new_vmlinux = vmlinux.replace(initrd_xz,new_initrd_xz)
    new_vmlinux_xz = lzma.compress(new_vmlinux,check=lzma.CHECK_CRC32,filters=[{"id": lzma.FILTER_LZMA2, "preset": 9,}] )
    assert len(new_vmlinux_xz) <= len(vmlinux_xz),'new vmlinux xz size is too big'
    print(f'new vmlinux xz size:{len(new_vmlinux_xz)}')
    print(f'old vmlinux xz size:{len(vmlinux_xz)}')
    print(f'ljust size:{len(vmlinux_xz)-len(new_vmlinux_xz)}')
    new_vmlinux_xz = new_vmlinux_xz.ljust(len(vmlinux_xz),b'\0')
    new_data = data.replace(vmlinux_xz,new_vmlinux_xz)
    return new_data

def build_efi(input_file, output_file):
    def find_xz_streams(data:bytes):
        streams = []
        XZ_HEADER_MAGIC = b'\xFD7zXZ\x00\x00\x01'
        XZ_FOOTER_MAGIC = b'\x00\x00\x00\x00\x01\x59\x5A'
        i = 0
        while True:
            start = data.find(XZ_HEADER_MAGIC, i)
            if start == -1:
                break
            end = data.find(XZ_FOOTER_MAGIC, start)
            assert end != -1, 'XZ footer not found'
            end += len(XZ_FOOTER_MAGIC)
            streams.append((start, end))
            i = end
        return streams
    with open(input_file, 'rb') as f:
        elf = ELFFile(f)
        initrd_section =elf.get_section_by_name('initrd')
        assert initrd_section is not None,'initrd section not found'
        initrd_data = initrd_section.data()
        xz_streams = find_xz_streams(initrd_data)
        assert len(xz_streams) == 2,'only support 2 xz streams'
        efi_xz = initrd_data[xz_streams[0][0]:xz_streams[0][1]]
        cpio_xz = initrd_data[xz_streams[1][0]:xz_streams[1][1]]
        try:
            efi = lzma.decompress(efi_xz)
        except Exception as e:
            print(f'size:{len(efi_xz)},header:{efi_xz[:20].hex().upper()},footer:{efi_xz[-20:].hex().upper()}\n')
            raise Exception(f'failed to decompress efi: {e}')

        with pefile.PE(data = efi) as pe:
            data_section =[section for section in pe.sections if section.Name == b'.data\x00\x00\x00'][0]
            rva = data_section.VirtualAddress
            addr = data_section.PointerToRawData
            data = data_section.get_data()
            size = len(data)
            alignment = ((rva + size) + 4096 - 1) & ~(4096 - 1) #4096对齐
            alignment = alignment - (rva+size)
            new_data = data + b'\x00'*alignment
            new_data += struct.pack('<I',len(cpio_xz))
            new_data += cpio_xz
            data_section.SizeOfRawData = len(new_data)
            new_file_data = pe.write()
            new_file_data = new_file_data[:addr]
            new_file_data += new_data
            with open(output_file, 'wb') as f:
                f.write(new_file_data)

def patch_netinstall(key_dict: dict,input_file,output_file=None):
    netinstall = open(input_file,'rb').read()
    if netinstall[:2] == b'MZ':
        ROUTEROS_BOOT = {
            129:{'arch':'power','name':'Powerboot'},
            130:{'arch':'e500','name':'e500_boot'},
            131:{'arch':'mips','name':'Mips_boot'},
            135:{'arch':'400','name':'440__boot'},
            136:{'arch':'tile','name':'tile_boot'},
            137:{'arch':'arm','name':'ARM__boot'},
            138:{'arch':'mmips','name':'MMipsBoot'},
            139:{'arch':'arm64','name':'ARM64__boot'},
            143:{'arch':'x86_64','name':'x86_64boot'}
        }
        with pefile.PE(input_file) as pe:
            for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource.id == pefile.RESOURCE_TYPE["RT_RCDATA"]:
                    for sub_resource in resource.directory.entries:
                        if sub_resource.id in ROUTEROS_BOOT:
                            bootloader = ROUTEROS_BOOT[sub_resource.id]
                            print(f'found {bootloader["arch"]}({sub_resource.id}) bootloader')
                            rva = sub_resource.directory.entries[0].data.struct.OffsetToData
                            size = sub_resource.directory.entries[0].data.struct.Size
                            data = pe.get_data(rva,size)
                            _size = struct.unpack('<I',data[:4])[0]
                            _data = data[4:4+_size]
                            try:
                                if _data[:2] == b'MZ':
                                    new_data = patch_pe(_data,key_dict)
                                elif _data[:4] == b'\x7FELF':
                                    new_data = patch_elf(_data,key_dict)
                                else:
                                    raise Exception(f'unknown bootloader format {_data[:4].hex().upper()}')
                            except Exception as e:
                                print(f'patch {bootloader["arch"]}({sub_resource.id}) bootloader failed {e}')
                                new_data = _data
                            new_data = struct.pack("<I",_size) + new_data.ljust(len(_data),b'\0')
                            new_data = new_data.ljust(size,b'\0')
                            pe.set_bytes_at_rva(rva,new_data)
            pe.write(output_file or input_file)
    elif netinstall[:4] == b'\x7FELF':
        # 83 00 00 00 C4 68 C4 0B  5A C2 04 08 10 9E 52 00
        # 8A 00 00 00 C3 68 C4 0B  6A 60 57 08 C0 3D 54 00
        # 81 00 00 00 D3 68 C4 0B  2A 9E AB 08 5C 1B 78 00
        # 82 00 00 00 E8 6B C4 0B  86 B9 23 09 78 01 82 00
        # 87 00 00 00 ED 6B C4 0B  FE BA A5 09 44 BF 7B 00
        # 89 00 00 00 0C 6A C4 0B  42 7A 21 0A C4 1D 3E 00
        # 8B 00 00 00 1E 69 C4 0B  06 98 5F 0A 28 95 5E 00
        # 8C 00 00 00 F1 6B C4 0B  2E 2D BE 0A 78 EA 5D 00
        # 88 00 00 00 03 69 C4 0B  A6 17 1C 0B 28 55 4A 00
        # 8F 00 00 00 FC 6B C4 0B  CE 6C 66 0B E0 E8 58 00
        SECTION_HEADER_OFFSET_IN_FILE = struct.unpack_from(b'<I',netinstall[0x20:])[0]
        SECTION_HEADER_ENTRY_SIZE = struct.unpack_from(b'<H',netinstall[0x2E:])[0]
        NUMBER_OF_SECTION_HEADER_ENTRIES = struct.unpack_from(b'<H',netinstall[0x30:])[0]
        STRING_TABLE_INDEX = struct.unpack_from(b'<H',netinstall[0x32:])[0]
        section_name_offset = SECTION_HEADER_OFFSET_IN_FILE + STRING_TABLE_INDEX * SECTION_HEADER_ENTRY_SIZE + 16
        SECTION_NAME_BLOCK = struct.unpack_from(b'<I',netinstall[section_name_offset:])[0]
        for i in range(NUMBER_OF_SECTION_HEADER_ENTRIES):
            section_offset = SECTION_HEADER_OFFSET_IN_FILE + i * SECTION_HEADER_ENTRY_SIZE
            name_offset,_,_,addr,offset = struct.unpack_from('<IIIII',netinstall[section_offset:])
            name = netinstall[SECTION_NAME_BLOCK+name_offset:].split(b'\0')[0]
            if name == b'.text':
                print(f'found .text section at {hex(offset)} addr {hex(addr)}')
                text_section_addr = addr
                text_section_offset = offset
                break
        offset = re.search(rb'\x83\x00\x00\x00.{12}\x8A\x00\x00\x00.{12}\x81\x00\x00\x00.{12}',netinstall).start()
        print(f'found bootloaders offset {hex(offset)}')
        for i in range(10):
            id,name_ptr,data_ptr,data_size = struct.unpack_from('<IIII',netinstall[offset+i*16:offset+i*16+16])
            name = netinstall[text_section_offset+name_ptr-text_section_addr:].split(b'\0')[0]
            data = netinstall[text_section_offset+data_ptr-text_section_addr:text_section_offset+data_ptr-text_section_addr+data_size]
            print(f'found {name.decode()}({id}) bootloader offset {hex(text_section_offset+data_ptr-text_section_addr)} size {data_size}')
            try:
                if data[:2] == b'MZ':
                    new_data = patch_pe(data,key_dict)
                elif data[:4] == b'\x7FELF':
                    new_data = patch_elf(data,key_dict)
                else:
                    raise Exception(f'unknown bootloader format {data[:4].hex().upper()}')
            except Exception as e:
                print(f'patch {name.decode()}({id}) bootloader failed {e}')
                new_data = data
            new_data = new_data.ljust(len(data),b'\0')
            netinstall = netinstall.replace(data,new_data)
        open(output_file or input_file,'wb').write(netinstall)

def patch_kernel(data:bytes,key_dict):
    if data[:2] == b'MZ':
        print('patching EFI Kernel')
        if data[56:60] == b'ARM\x64':
            print('patching arm64')
            return patch_elf(data,key_dict)
        else:
            print('patching x86_64')
            return patch_bzimage(data,key_dict)
    elif data[:4] == b'\x7FELF':
        print('patching ELF')
        return patch_elf(data,key_dict)
    elif data[:5] == b'\xFD7zXZ':
        print('patching initrd')
        return patch_initrd_xz(data,key_dict,False)
    else:
        raise Exception('unknown kernel format')

def patch_loader(loader_file):

    # ==========================================
    # 🌟 优化 1：双重架构探测机制
    # ==========================================
    arch = os.getenv('ARCH')
    if not arch:
        # 如果没有读取到环境变量，智能从命令行运行参数中推断架构
        full_args = " ".join(sys.argv).lower()
        if "arm64" in full_args:
            arch = "arm64"
        elif "x86" in full_args:
            arch = "x86"
        elif "mipsbe" in full_args:
            arch = "mipsbe"
        else:
            arch = "x86"  # 终极保底值
            
    arch = arch.replace('-', '')
    
    # 2. 获取当前版本号字符串 (如 "7.21.3" 或 "7.24beta3")
    version_str = os.getenv('VERSION', '7.22.3')
    
    # 3. 提取版本号的前两个数字，例如 "7.24beta3" -> ['7', '24', '3'] -> "7.24"
    nums = re.findall(r'\d+', version_str)
    if len(nums) >= 2:
        version_major_minor = f"{nums[0]}.{nums[1]}"  # 提取出 "7.21"、"7.24"
    else:
        version_major_minor = "7.22"  # 默认安全回退值
        print(f"[!] 警告：未能成功解析版本号 '{version_str}'，默认使用 {version_major_minor}")
    
    # 4. 动态拼接文件名（例如: loader_arm64_7.24）
    filename = f"loader_{arch}_{version_major_minor}"
    
    # 5. 拼接至仓库根目录下的 loader 文件夹中
    custom_loader_source = os.path.join("loader", filename)
    
    # 6. 执行文件拷贝与权限赋予
    if os.path.exists(custom_loader_source):
        print(f"[*] 成功识别版本 v{version_str} ({arch}架构)，正在拷贝 {custom_loader_source} ...")
        shutil.copy2(custom_loader_source, loader_file)
        
        # 强制赋予 0755 可执行权限
        os.chmod(loader_file, 0o755)
        print(f"[+] 替换成功并已成功赋予 0755 执行权限！")
    else:
        print(f"[!] 警告：未在仓库目录下找到预制的引导文件 {custom_loader_source} ，跳过覆盖！")

    # 1. 获取 loader_file 所在的目录，以便将 mode 文件拷贝到同级目录
    target_dir = os.path.dirname(loader_file)
    # 目标文件的完整路径 (例如: /path/to/target/mode)
    mode_target_file = os.path.join(target_dir, "mode")
    
    # 2. 动态拼接源 mode 文件名（例如: mode_arm64 或 mode_x86）
    mode_filename = f"mode_{arch}"
    
    # 3. 拼接至仓库根目录下的 mode 文件夹中 (例如: mode/mode_arm64)
    custom_mode_source = os.path.join("mode", mode_filename)
    
    # 4. 执行 mode 文件的拷贝与权限赋予
    if os.path.exists(custom_mode_source):
        print(f"[*] 找到对应架构的 mode 文件，正在拷贝 {custom_mode_source} 到 {mode_target_file} ...")
        shutil.copy2(custom_mode_source, mode_target_file)
        
        # 强制赋予 0755 可执行权限
        os.chmod(mode_target_file, 0o755)
        print(f"[+] Mode 文件替换成功并已成功赋予 0755 执行权限！")
    else:
        print(f"[!] 警告：未在仓库目录下找到预制的 mode 文件 {custom_mode_source} ，跳过 mode 覆盖！")
        
def patch_squashfs(path, key_dict):
    # 1. 整理所有的 URL 和 公钥替换对（已补上 MIKRO_CLOUD2_URL）
    url_replacements = {
        os.environ.get('MIKRO_LICENCE_URL', '').encode(): os.environ.get('CUSTOM_LICENCE_URL', '').encode(),
        os.environ.get('MIKRO_UPGRADE_URL', '').encode(): os.environ.get('CUSTOM_UPGRADE_URL', '').encode(),
        os.environ.get('MIKRO_CLOUD_URL', '').encode(): os.environ.get('CUSTOM_CLOUD_URL', '').encode(),
        os.environ.get('MIKRO_CLOUD2_URL', '').encode(): os.environ.get('CUSTOM_CLOUD2_URL', '').encode(),  # 新增
   #     os.environ.get('MIKRO_CLOUD_PUBLIC_KEY', '').encode(): os.environ.get('CUSTOM_CLOUD_PUBLIC_KEY', '').encode(),
    }
    # 过滤掉空的替换对
    url_replacements = {k: v for k, v in url_replacements.items() if k and v}

    # 专门针对续期文件的替换
    renew_replacements = {
        os.environ.get('MIKRO_RENEW_URL', '').encode(): os.environ.get('CUSTOM_RENEW_URL', '').encode(),
    }
    renew_replacements = {k: v for k, v in renew_replacements.items() if k and v}

    for root, dirs, files in os.walk(path):
        for _file in files:
            file_path = os.path.join(root, _file)
            if not os.path.isfile(file_path):
                continue

            # === loader 特殊处理 ===
            if _file == 'loader':
                patch_loader(file_path)
                continue

            # === BOOTX64.EFI 特殊处理（来自方法二） ===
            if _file == 'BOOTX64.EFI':
                with open(file_path, 'rb') as f:
                    data = f.read()
                new_data = patch_kernel(data, key_dict)
                assert new_data != data, f'{file_path} key not patched'
                with open(file_path, 'wb') as f:
                    f.write(new_data)
                continue

            # 1. 读取文件
            data = open(file_path, 'rb').read()
            original_data = data

            # 2. 替换公钥 (License Public Key)
            for old_public_key, new_public_key in key_dict.items():
                data = replace_key(old_public_key, new_public_key, data, file_path)

            # 3. 替换常规的 URL 和云端公钥
            for old_url, new_url in url_replacements.items():
                if old_url in data:
                    print(f'{file_path} url/cloud-key patched')
                    data = data.replace(old_url, new_url)

            # 4. 针对 licupgr 文件的特殊 Renew URL 替换（来自方法二的判断逻辑）
            if _file == 'licupgr':
                for old_url, new_url in renew_replacements.items():
                    if old_url in data:
                        print(f'{file_path} renew url patched')
                        data = data.replace(old_url, new_url)

            # 5. 如果内容有变动，写回文件
            if data != original_data:
                open(file_path, 'wb').write(data)
                    
def run_shell_command(command):
    process = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process.stdout, process.stderr

def patch_npk_package(package,key_dict):
    if package[NpkPartID.NAME_INFO].data.name == 'system':
        file_container = NpkFileContainer.unserialize_from(package[NpkPartID.FILE_CONTAINER].data)
        for item in file_container:
            if item.name in [b'boot/EFI/BOOT/BOOTX64.EFI',b'boot/kernel',b'boot/initrd.rgz']:
                print(f'patch {item.name} ...')
                item.data = patch_kernel(item.data,key_dict)
        package[NpkPartID.FILE_CONTAINER].data = file_container.serialize()
        with tempfile.TemporaryDirectory() as tmp_dir:
            squashfs_file = os.path.join(tmp_dir, 'squashfs-root.sfs')
            extract_dir = os.path.join(tmp_dir, 'squashfs-root')
            with open(squashfs_file,'wb') as f:
                f.write(package[NpkPartID.SQUASHFS].data)
            print(f"extract {squashfs_file} ...")
            run_shell_command(f"unsquashfs -d {extract_dir} {squashfs_file}")
            patch_squashfs(extract_dir,key_dict)
            run_shell_command(f"mksquashfs {extract_dir} {squashfs_file} -no-recovery -noappend -exit-on-error -quiet -comp xz -no-xattrs -b 256k -all-root")
            with open(squashfs_file,'rb') as f:
                package[NpkPartID.SQUASHFS].data = f.read()

def patch_npk_file(key_dict,kcdsa_private_key,eddsa_private_key,input_file,output_file=None):
    npk = NovaPackage.load(input_file)   
    if len(npk._packages) > 0:
        for package in npk._packages:
            patch_npk_package(package,key_dict)
    else:
        patch_npk_package(npk,key_dict)
    npk.sign(kcdsa_private_key,eddsa_private_key)
    npk.save(output_file or input_file)

if __name__ == '__main__':
    import argparse,os
    parser = argparse.ArgumentParser(description='MikroTik patcher')
    subparsers = parser.add_subparsers(dest="command")
    npk_parser = subparsers.add_parser('npk',help='patch and sign npk file')
    npk_parser.add_argument('input',type=str, help='Input file')
    npk_parser.add_argument('-O','--output',type=str,help='Output file')
    kernel_parser = subparsers.add_parser('kernel',help='patch kernel file')
    kernel_parser.add_argument('input',type=str, help='Input file')
    kernel_parser.add_argument('-O','--output',type=str,help='Output file')
    buildefi_parser = subparsers.add_parser('buildefi',help='build efi file')
    buildefi_parser.add_argument('input',type=str, help='kernel file')
    buildefi_parser.add_argument('output',type=str,help='Output to file')
    netinstall_parser = subparsers.add_parser('netinstall',help='patch netinstall file')
    netinstall_parser.add_argument('input',type=str, help='Input file')
    netinstall_parser.add_argument('-O','--output',type=str,help='Output file')
    block_parser = subparsers.add_parser('block', help='patch file on block device (in-place)')
    block_parser.add_argument('dev', type=str, help='block device, e.g. /dev/nbd1p1')
    block_parser.add_argument('file', type=str, help='file path inside fs, e.g. EFI/BOOT/BOOTX64.EFI')
    args = parser.parse_args()
    key_dict = {
        bytes.fromhex(os.environ['MIKRO_LICENSE_PUBLIC_KEY']):bytes.fromhex(os.environ['CUSTOM_LICENSE_PUBLIC_KEY']),
        bytes.fromhex(os.environ['MIKRO_NPK_SIGN_PUBLIC_KEY']):bytes.fromhex(os.environ['CUSTOM_NPK_SIGN_PUBLIC_KEY'])
    }
    kcdsa_private_key = bytes.fromhex(os.environ['CUSTOM_LICENSE_PRIVATE_KEY'])
    eddsa_private_key = bytes.fromhex(os.environ['CUSTOM_NPK_SIGN_PRIVATE_KEY'])
    if args.command =='npk':
        print(f'patching {args.input} ...')
        patch_npk_file(key_dict,kcdsa_private_key,eddsa_private_key,args.input,args.output)
    elif args.command == 'kernel':
        print(f'patching {args.input} ...')
        data = patch_kernel(open(args.input,'rb').read(),key_dict)
        open(args.output or args.input,'wb').write(data)
    elif args.command == 'buildefi':
        print(f'building EFI from {args.input} ...')
        build_efi(args.input,args.output)
    elif args.command == 'netinstall':
        print(f'patching {args.input} ...')
        patch_netinstall(key_dict,args.input,args.output)
    elif args.command == 'block':
        print(f'patching {args.file} on {args.dev} ...')
        patch_block(args.dev, args.file, key_dict)
    else:
        parser.print_help()


    
