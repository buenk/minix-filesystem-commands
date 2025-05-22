'''
    Bestandsnaam:   mfstool.py
    Auteur:         W.E. Buenk
    UvAnetID:       15817814
    Studie:         BSc Informatica
    Datum:          20-05-2025

    Bechrijving:
    Dit bestand implementeert verschillende commandos om te interacteren met
    het MINIX filesystem. De functies zijn opgedeeld in verschillende functies,
    die gebruik maken van helper functies om hun doel te bereiken. De
    geïmplementeerde commando's zijn:
    - ls
    - cat
    - touch
    - mkdir
'''

import sys

import struct
import time

BLOCK_SIZE = 1024

S_IFMT = 0o170000
S_IFDIR = 0o040000
S_IFREG = 0o100000


def parse_superblock(sbdata):
    '''
    Parse the contents of the superblock struct and turn it into a dictionary.

    Args:
        sbdata (bytes): The byte data of the superblock struct.

    Returns:
        sbdict (dict): Dictionary with the unpacked values of the superblock.
    '''

    sbdict = {}
    idx = 0

    # The layout of the superblock struct.
    superblock_layout = [
        ("ninodes", "<H"),
        ("nzones", "<H"),
        ("imap_blocks", "<H"),
        ("zmap_blocks", "<H"),
        ("firstdatazone", "<H"),
        ("log_zone_size", "<H"),
        ("max_size", "<L"),
        ("magic", "<H"),
        ("state", "<H")
    ]

    # Populate the superblock dictionary.
    for name, fmt in superblock_layout:
        # '<' Means little-endian byte order, which is what MINIX uses.
        # 'H' means unsigned short. (type of s_inoes)
        # Then slice the first 2 bytes from sbdata.
        size = struct.calcsize(fmt)
        (sbdict[name],) = struct.unpack(fmt, sbdata[idx: idx + size])
        idx += size

    return sbdict


def parse_inode(indata):
    '''
    Parse the contents of an Inode struct and turn it into a dictionary.

    Args:
        indata (bytes): The byte data of the Inode struct.

    Returns:
        indict (dict): Dictionary with the unpacked values of the Inode.
    '''

    indict = {}
    idx = 0

    # The layout of the inode struct.
    inode_layout = [
        ("i_mode",   "<H"),
        ("i_uid",    "<H"),
        ("i_size",   "<L"),
        ("i_time",   "<L"),
        ("i_gid",    "<B"),
        ("i_nlinks", "<B"),
        ("i_zone",   "<9H")   # Array of 9
    ]

    # Populate the inode dictionary.
    for name, fmt in inode_layout:
        size = struct.calcsize(fmt)

        if name == "i_zone":
            indict[name] = struct.unpack(fmt, indata[idx: idx + size])
        else:
            (indict[name],) = struct.unpack(fmt, indata[idx: idx + size])

        idx += size

    return indict


def iterate_dir_entries(directory_inode_dict, f):
    '''
    Iterate over directory entries within a given directory's data blocks.

    This is a generator function. This generator reads through the data zones
    from directory_inode_dict. For each valid directory entry, it yields the
    inode number and the raw filename.

    NOTE: This implementation only processes direct data blocks.

    Args:
        directory_inode_dict (dict):    Parsed Inode dictionary of the
                                        directory to be read.
        f (file object):                Open file object for the disk image.

    Yields:
        tuple: A tuple of (inode_num, byte_string_name):
            inode_num (int):            Inode number of the directory entry.
            byte_string_name (bytes):   Raw filename of the directory entry.
    '''

    total_bytes_processed = 0
    total_dir_content_size = directory_inode_dict["i_size"]

    # Loop over the total 7 direct data blocks.
    for i in range(7):
        if total_bytes_processed >= total_dir_content_size:
            break  # Processed all content.

        if directory_inode_dict["i_zone"][i] == 0:
            break  # No more used data blocks.

        # Get the data block location pointer. (where the directory is stored)
        data_block_offset = directory_inode_dict["i_zone"][i] * BLOCK_SIZE

        # Move to the location and get the raw directory content.
        f.seek(data_block_offset)
        block_content = f.read(BLOCK_SIZE)

        # Loop until we have reached the end of the data block.
        current_byte_offset = 0
        while current_byte_offset < BLOCK_SIZE:
            if total_bytes_processed >= total_dir_content_size:
                break

            current_data = block_content[
                current_byte_offset: current_byte_offset + DIR_ENTRY_SIZE
            ]

            (inode_num,) = struct.unpack("<H", current_data[0: 2])
            current_byte_offset += DIR_ENTRY_SIZE

            if inode_num == 0:
                continue  # Do not check empty inodes.

            total_bytes_processed += DIR_ENTRY_SIZE
            byte_string_name = current_data[2: 2 + FILENAME_LEN]

            yield (inode_num, byte_string_name)


def find_empty_inode_slot(sbdict, inode_map):
    '''
    Find an empty inode inside of the inode map. If an empty slot is found
    return the number of the free inode, return -1 otherwise.

    Args:
        sbdict (dict):          Parsed superblock data.
        inode_map (bytearray):  Byte-array of the Inode Map.

    Returns:
        free_inode (int): Number of the free inode that is found, -1 otherwise.
    '''

    total_inodes = sbdict["ninodes"]
    free_inode = -1
    for i in range(1, total_inodes):
        byte_index = i // 8
        bit_index = i % 8

        if byte_index < len(inode_map):
            byte = inode_map[byte_index]

            if ((byte >> bit_index) & 1) == 0:
                # Found a free inode bit
                free_inode = i
                break
        else:
            break

    return free_inode


def update_i_size(dir_inode_dict, itable_location, f, offset):
    '''
    Update the i_size field of a given directory's inode, using a given
    directory size, if the new entry att offset extends the directory's size.

    Args:
        dir_inode_dict (dict):  Parsed inode data of the directory.
        itable_location (int):  Location of the Inode Table in blocks.
        f (file object):        Open file object for the disk image.
        offset (int):           The byte offset within the directory's data
                                where the new entry was placed.
    '''

    current_isize = dir_inode_dict["i_size"]
    end_of_new_entry = offset + DIR_ENTRY_SIZE
    new_isize = current_isize

    if end_of_new_entry > current_isize:
        new_isize = end_of_new_entry
    elif new_isize == current_isize:
        return

    updated_root_inode_data = bytes()
    updated_root_inode_data += struct.pack("<H", dir_inode_dict["i_mode"])
    updated_root_inode_data += struct.pack("<H", dir_inode_dict["i_uid"])
    updated_root_inode_data += struct.pack("<L", new_isize)
    updated_root_inode_data += struct.pack("<L", dir_inode_dict["i_time"])
    updated_root_inode_data += struct.pack("<B", dir_inode_dict["i_gid"])
    updated_root_inode_data += struct.pack("<B", dir_inode_dict["i_nlinks"])
    updated_root_inode_data += struct.pack("<9H", *dir_inode_dict["i_zone"])

    f.seek(itable_location * BLOCK_SIZE)
    f.write(updated_root_inode_data)
    f.flush()


def find_empty_slot(dir_content):
    '''
    Find and return the byte offset of the first empty slot inside of a given
    directory. Return -1 if no empty slot is found.

    Args:
        dir_content (list):     Contents of the directory.

    Returns:
        offset_empty_slot (int):    The byte offset of the found empty slot, -1
                                    if no emtpy slot is found.
    '''

    current_byte_offset = 0
    offset_empty_slot = -1
    while current_byte_offset + DIR_ENTRY_SIZE <= len(dir_content):
        current_slice = dir_content[
            current_byte_offset: current_byte_offset + DIR_ENTRY_SIZE
        ]

        inode_num_bytes = current_slice[0: 2]
        (slot_inode_num,) = struct.unpack("<H", inode_num_bytes)

        if slot_inode_num == 0:
            offset_empty_slot = current_byte_offset
            break

        current_byte_offset += DIR_ENTRY_SIZE

    return offset_empty_slot


def transform_filename(filename, filename_length):
    '''
    Encode a filename string in ascii and pad it to achieve a certain filename
    length. Return an encoded and padded filename or None if the filename is
    too long.

    Args:
        filename (string):      Filename to be transformed.
        filename_length (int):  The length of the final filename.

    Returns:
        final_filename (string): The encoded and padded filename. None if the
        filename is too long
    '''

    encoded_filename = filename.encode("ascii")

    # Pad the filename.
    padding_len = filename_length - len(encoded_filename)
    if padding_len < 0:
        return
    elif padding_len > 0:
        final_filename = encoded_filename + (b'\0' * padding_len)
    else:
        final_filename = encoded_filename

    return final_filename


def find_empty_zone_slot(sbdict, zone_map):
    '''
    Find an empty zone inside of the zone map. If an empty slot is found
    return the number of the free zone, return -1 otherwise.

    Args:
        sbdict (dict):          Parsed superblock data.
        zone_map (bytearray):   Byte-array of the Zone Map.

    Returns:
        free_zone (int): Number of the free zone that is found, -1 otherwise.
    '''

    total_zones = sbdict["nzones"]
    free_zone = -1
    for i in range(1, total_zones):
        byte_index = i // 8
        bit_index = i % 8

        if byte_index < len(zone_map):
            byte = zone_map[byte_index]

            if ((byte >> bit_index) & 1) == 0:
                # Found a free zone bit
                free_zone = i
                break
        else:
            break

    return free_zone


def update_zone_map(zone_map, f, free_zone):
    '''
    Update the bit of a certain zone in the zone map to 1 for a given zone
    number.

    Args:
        zone_map (int):     The zone Map location.
        f (file object):    Open file object for the disk image.
        free_zone (int):    The number of the free zone.
    '''

    zone_byte_index = free_zone // 8
    zone_bit_index = free_zone % 8
    mask = 1 << zone_bit_index

    zone_map[zone_byte_index] = zone_map[zone_byte_index] | mask
    f.seek(2 * BLOCK_SIZE)
    f.write(zone_map)
    f.flush()


def pack_and_write_empty_dir(free_zone, current_dir, f, sbdict):
    '''
    Pack a directory entry struct for an emptry directory, containg "." and
    "..". Write it to the data zone.

    Args:
        free_zone (int):        Number of the free data zone.
        current_dir (int):      Number of the Inode of the current directory.
        f (file object):        Open file object for the disk image.
        sbdict (dict):          Parsed superblock data.
    '''

    new_data_zone = bytearray(BLOCK_SIZE)
    dot_inode = struct.pack("<H", current_dir)
    dot_inode += transform_filename(".", FILENAME_LEN)

    ddot_inode = struct.pack("<H", 1)  # Hard-coded for root directory
    ddot_inode += transform_filename("..", FILENAME_LEN)

    new_data_zone[0: DIR_ENTRY_SIZE] = dot_inode
    new_data_zone[DIR_ENTRY_SIZE: DIR_ENTRY_SIZE * 2] = ddot_inode

    f.seek(((sbdict['firstdatazone'] - 1) + free_zone) * BLOCK_SIZE)
    f.write(new_data_zone)
    f.flush()


def initialize_and_write_inode(
        f,
        free_inode,
        itable_location,
        obj_type,
        sbdict
):
    '''
    Initialize an Inode struct for an empty file or directory and write it to
    the Inode Table.

    Args:
        f (file ojbect):        Open file object for the MINIX disk image.
        free_inode (int):       Number of the free Inode.
        itable_location (int):  Location of the Inode Table.
        obj_type (int):         1 for files, 2 for directories.
    '''

    if obj_type == 1:
        i_mode = S_IFREG | 0o400 | 0o200 | 0o100
        i_size = 0
        i_nlinks = 1
        izone_values = (0,) * 9
    elif obj_type == 2:
        i_mode = S_IFDIR | 0o755
        i_size = (FILENAME_LEN + 2) * 2
        i_nlinks = 2

        zmap_size = sbdict["zmap_blocks"] * BLOCK_SIZE
        f.seek((2 + sbdict["imap_blocks"]) * BLOCK_SIZE)  # Location of Zmap
        zone_map = bytearray(f.read(zmap_size))

        free_zone = find_empty_zone_slot(sbdict, zone_map)
        if free_zone == -1:
            sys.stderr.write("Error: No free data zone found.\n")
            return

        update_zone_map(zone_map, f, free_zone)
        izone_values = (free_zone, 0, 0, 0, 0, 0, 0, 0, 0)

        pack_and_write_empty_dir(free_zone, free_inode, f, sbdict)
    else:
        sys.stderr.write("Improper object type.\n")
        return

    new_inode_data = bytes()
    new_inode_data += struct.pack("<H", i_mode)
    new_inode_data += struct.pack("<H", 0)
    new_inode_data += struct.pack("<L", i_size)
    new_inode_data += struct.pack("<L", int(time.time()))
    new_inode_data += struct.pack("<B", 0)
    new_inode_data += struct.pack("<B", i_nlinks)
    new_inode_data += struct.pack("<9H", *izone_values)

    offset_in_inode_table = (free_inode - 1) * 32
    f.seek(itable_location * BLOCK_SIZE + offset_in_inode_table)
    f.write(new_inode_data)
    f.flush()


def update_inode_map(inode_map, f, free_inode):
    '''
    Update the bit of a certain Inode in the Inode map to 1 for a given Inode
    number.

    Args:
        inode_map (int):    The Inode Map location.
        f (file object):    Open file object for the disk image.
        free_inode (int):   The number of the free Inode.
    '''

    inode_byte_index = free_inode // 8
    inode_bit_index = free_inode % 8
    mask = 1 << inode_bit_index

    inode_map[inode_byte_index] = inode_map[inode_byte_index] | mask
    f.seek(2 * BLOCK_SIZE)
    f.write(inode_map)
    f.flush()


def write_dir_entry(f, itable_location, dir_entry_name, inode_num):
    '''
    Find an empty slot in the root directory data block. Write a new directory
    entry to it, and update i_size afterwards.

    Args:
        f (file object):            Open file object for the disk image.
        itable_location (int):      Location of the Inode Table in blocks.
        dir_entry_name (string):    Name of the directory entry to write.
        inode_num (int):           Number of the inode of the directory entry.
    '''

    # Retrieve and parse the root inode.
    f.seek(itable_location * BLOCK_SIZE)
    root_inode_dict = parse_inode(f.read(32))
    data_block_offset = root_inode_dict["i_zone"][0] * BLOCK_SIZE

    # Move to the location and get the raw directory content.
    f.seek(data_block_offset)
    root_dir_content = bytearray(f.read(BLOCK_SIZE))

    offset_empty_slot = find_empty_slot(root_dir_content)
    if offset_empty_slot == -1:
        sys.stderr.write("No emtpy slot found inside root directory.\n")
        return

    # Construct the file struct.
    new_dir_entry_data = bytes()
    new_dir_entry_data += struct.pack("<H", inode_num)

    new_dir_entry_name = transform_filename(dir_entry_name, FILENAME_LEN)
    if new_dir_entry_name is None:
        sys.stderr.write("File name is too long!\n")
        return
    new_dir_entry_data += new_dir_entry_name

    root_dir_content[
        offset_empty_slot: offset_empty_slot + DIR_ENTRY_SIZE
    ] = new_dir_entry_data

    f.seek(data_block_offset)
    f.write(root_dir_content)

    update_i_size(
        root_inode_dict,
        itable_location,
        f,
        offset_empty_slot
    )

    f.flush()


def find_entry_in_directory(entry_name, f, current_dir_inode):
    '''
    Look for a file with a certain name inside of a given directory. Return
    the Inode number of this directory entry.

    Args:
        entry_name (string):        Name of the file to be searched for.
        f (file object):            Open file object for the disk image.
        current_dir_inode (dict):   Parsed Inode dictionary of the directory
                                    to search.

    Returns:
        inode_num if a directory, was found otherwise -1:
            inode_num (int):    The number of the found directory entry.
    '''

    byte_string_target = entry_name.encode("ascii")

    for inode_num, byte_string_name in iterate_dir_entries(
        current_dir_inode,
        f
    ):
        stripped_name = byte_string_name.rstrip(b'\0')
        if stripped_name == byte_string_target:
            return inode_num

    # Entry was not found
    return -1


def ls_command(sbdict, f):
    '''
    List all files and directories in the root directory and write it to
    standard out. Uses the iterate_dir_entries generator function to loop over
    all directory entries.

    Args:
        sbdict (dict):      Parsed superblock data.
        f (file object):    Open file object for the disk image.
    '''

    # Calculate the location of the inode map.
    itable_location = 2 + sbdict["imap_blocks"] + sbdict["zmap_blocks"]

    # Retrieve and parse the root inode.
    f.seek(itable_location * BLOCK_SIZE)
    root_inode_dict = parse_inode(f.read(32))

    for _, byte_string_name in iterate_dir_entries(
        root_inode_dict,
        f
    ):
        printname = byte_string_name.rstrip(b'\0')
        sys.stdout.buffer.write(printname)
        sys.stdout.buffer.write(b'\n')
        sys.stdout.flush()


def touch_command(sbdict, f, filename):
    '''
    Create an emtpy file with a given filename and write it to the root
    directory of the MINIX filesystem. This is done in the following steps:
        Allocate a free inode from the Inode map.
        Initialize this inode inside of the Inode table.
        Write the directory entry to the data block.

    Args:
        sbdict (dict):      Parsed superblock data.
        f (file object):    Open file object for the disk image,
                            needs to be in 'r+b'.
        filename (string):  Name of the file to be created.
    '''

    itable_location = 2 + sbdict["imap_blocks"] + sbdict["zmap_blocks"]
    imap_size = sbdict["imap_blocks"] * BLOCK_SIZE

    f.seek(2 * BLOCK_SIZE)  # Location of Imap
    inode_map = bytearray(f.read(imap_size))

    free_inode = find_empty_inode_slot(sbdict, inode_map)
    if (free_inode == -1):
        return

    update_inode_map(inode_map, f, free_inode)
    initialize_and_write_inode(f, free_inode, itable_location, 1, sbdict)
    write_dir_entry(f, itable_location, filename, free_inode)


def mkdir_command(sbdict, f, dirname):
    '''
    Create an emtpy directory with a given name and write it to the root
    directory of the MINIX filesystem. This is done in the following steps:
        Allocate a free inode from the Inode map.
        Initialize this inode inside of the Inode table.
        Find an empty slot in the root directory data block.
        Write the new directory entry.
        Update i_size.

    Args:
        sbdict (dict):      Parsed superblock data.
        f (file object):    Open file object for the disk image,
                            needs to be in 'r+b'.
        dirname (string):   Name of the directory to be created.
    '''

    itable_location = 2 + sbdict["imap_blocks"] + sbdict["zmap_blocks"]
    imap_size = sbdict["imap_blocks"] * BLOCK_SIZE

    f.seek(2 * BLOCK_SIZE)  # Location of Imap
    inode_map = bytearray(f.read(imap_size))

    free_inode = find_empty_inode_slot(sbdict, inode_map)
    if (free_inode == -1):
        return

    update_inode_map(inode_map, f, free_inode)
    initialize_and_write_inode(f, free_inode, itable_location, 2, sbdict)

    write_dir_entry(f, itable_location, dirname, free_inode)


def cat_command(sbdict, f, filepath):
    '''
    Get the contents of a file and print it. Iterates through the file system
    starting at the root directory, until the file is found. If a file or
    directory is not found, an error message is sent to standard error.

    Args:
        sbdict (dict):      Parsed superblock data.
        f (file object):    Open file object for the disk image.
        filename (string):  Name of the file to be created.
    '''
    itable_location = 2 + sbdict["imap_blocks"] + sbdict["zmap_blocks"]

    current_inode_num = 1
    parsed_filepath = filepath.split("/")
    final_inode = None

    for idx, component_name in enumerate(parsed_filepath):
        f.seek(itable_location * BLOCK_SIZE + (current_inode_num - 1) * 32)
        current_dir_inode = parse_inode(f.read(32))

        is_last_component = (idx == len(parsed_filepath) - 1)

        # Check if the entry is direcotry
        filetype = current_dir_inode["i_mode"] & S_IFMT
        if filetype == S_IFDIR:
            # It is a directory

            next_inode_num = find_entry_in_directory(
                component_name,
                f,
                current_dir_inode
            )

            if next_inode_num == -1:
                sys.stderr.write("Error: Directory not found.\n")
                return

            current_inode_num = next_inode_num
        elif is_last_component:
            # The last component has been reached
            final_inode = current_dir_inode
            break
        else:
            # Not a directory.
            sys.stderr.write("Error: Not a directory.\n")
            return

    if final_inode is None:
        f.seek(itable_location * BLOCK_SIZE + (current_inode_num - 1) * 32)
        final_inode = parse_inode(f.read(32))

    if final_inode is None:
        sys.stderr.write("Error: File not found.\n")
        return

    filetype = final_inode["i_mode"] & S_IFMT
    if filetype != S_IFREG:
        sys.stderr.write(f"Error: {filepath} is an unsupported file.\n")
        return

    filesize = final_inode["i_size"]
    bytes_read = 0
    for i in range(7):
        if bytes_read >= filesize:
            break

        zone_num = final_inode["i_zone"][i]
        if zone_num == 0:
            break

        f.seek(zone_num * BLOCK_SIZE)

        read_amount = min(BLOCK_SIZE, filesize - bytes_read)
        content = f.read(read_amount)
        sys.stdout.buffer.write(content)
        bytes_read += len(content)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: mfstool.py image command params")
        sys.exit(0)

    diskimg = sys.argv[1]
    cmd = sys.argv[2]

    with open(diskimg, "r+b") as f:
        f.seek(BLOCK_SIZE, 0)

        sbdata = f.read(BLOCK_SIZE)
        sbdict = parse_superblock(sbdata)

        global FILENAME_LEN
        if sbdict["magic"] == 0x137F:
            FILENAME_LEN = 14
        elif sbdict["magic"] == 0x138F:
            FILENAME_LEN = 30

        global DIR_ENTRY_SIZE
        DIR_ENTRY_SIZE = FILENAME_LEN + 2

        if cmd == "ls":
            ls_command(sbdict, f)
        if cmd == "touch":
            touch_command(sbdict, f, sys.argv[3])
        if cmd == "mkdir":
            mkdir_command(sbdict, f, sys.argv[3])
        if cmd == "cat":
            cat_command(sbdict, f, sys.argv[3])
