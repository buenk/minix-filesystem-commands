# MINIX Filesystem Commands
An implementation in python of various terminal commands to interact with the MINIX v1 filesystem. The implementation only works for direct data blocks. The following commands are implemented:  
- `ls` lists all the files in the root directory.  
- `cat` lists the content of a file in any directory.  
- `touch` creates an empty file in the root directory.  
- `mkdir` creates an empty directory in the root directory.  
You can read the file  'extended_introduction_to_minix_v1.pdf' for more context.  
## Usage
1. Create a MINIX disk image:  
```
dd if=/dev/zero of=disk1.img bs=1k count=1024
mkfs.minix -1 -n 14 disk1.img
```
2. Optionally, mount the disk image and create some files.
```
sudo mount -o loop disk1.img /mnt
touch /mnt/file0.txt
mkdir /mnt/dir1
```
3. Use the commands from the python program.  
```
python3 mfstool.py <disk name>.img <command> <args>
```
