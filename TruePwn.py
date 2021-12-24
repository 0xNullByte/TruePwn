from rich import print
from rich.layout import Layout, Panel
from rich.console import Console
from rich.text import Text
from rich.table import Table
from rich.syntax import Syntax
from pwn import ELF, subprocess
from getinfo import Function_names, disas, disassemble_main, Autopwn, Vuln_detect
import sys

def Style_(file):
	global layout, table, table2

	# @ layout
	layout = Layout(name="root")
	layout.split(
	        Layout(name="header", size=1),
	        Layout(name="main", ratio=1),
	    )
	layout["main"].split_row(
	        Layout(name="side"),
	        Layout(name="body", ratio=1, minimum_size=60,),

	    )
	layout["body"].split_column(
	        Layout(name="Function_name",size= 3 + len(file.functions) if len(file.functions) < 10 else 15 ),
	        Layout(name="disassemble"),
	    )
	layout["side"].split_column(
	        Layout(name="title",size=20,minimum_size=10),

	        Layout(name='app')
	    )
	# @ Tables 
	table = Table(expand=True)
	table2 = Table(expand=True)

# // Function Names 
	table.add_column("\t[b]Address[/]\t\t\t[b]Function name[/]", justify="left", style="cyan", no_wrap=True)
	table.add_row("[b]"	+ Function_names(file) + "[/]")
	layout['Function_name'].update(table)
	
# // disassemble
	table2.add_column(" [b]disassemble[/]  [cyan][b][ main ][/][/]", justify="left", style="cyan")
	table2.add_row(Syntax.from_path(disassemble_main(file)))

	layout['disassemble'].update(table2)

# // Title
	banner = '''
	 ███████████                               ███████████                            
	░█░░░███░░░█                              ░░███░░░░░███                           
	░   ░███  ░  ████████  █████ ████  ██████  ░███    ░███ █████ ███ █████ ████████  
	    ░███    ░░███░░███░░███ ░███  ███░░███ ░██████████ ░░███ ░███░░███ ░░███░░███ 
	    ░███     ░███ ░░░  ░███ ░███ ░███████  ░███░░░░░░   ░███ ░███ ░███  ░███ ░███ 
	    ░███     ░███      ░███ ░███ ░███░░░   ░███         ░░███████████   ░███ ░███ 
	    █████    █████     ░░████████░░██████  █████         ░░████░████    ████ █████
	   ░░░░░    ░░░░░       ░░░░░░░░  ░░░░░░  ░░░░░           ░░░░ ░░░░    ░░░░ ░░░░░  1.0\n\n'''

	checksec = '[red][*][/] CheckSec :\n\t' + elf.checksec().replace('\n','\n\t').replace('\x1b[33m','[yellow]').replace('\x1b[31m','[red]').replace('\x1b[32m','[green]').replace('\x1b[m','[/]')
	Vuln = f'\n\n[red][*][/] [b]Vuln functions : {Vuln_detect(elf)}[/]'
	layout['title'].update(Panel(banner + checksec + Vuln))


def app(elf,c):
	info = '''\n\n\n\n\n\n\n\n\n\n\n\n\n
	[b][[red]1[/]] Autopwn\t\t───>  Auto exploit & make script [/]
	[b][[red]2[/]] dis $function\t───>  Disassemble function by [ [cyan]Name or Address[/] ] [/]
	[b][[red]3[/]] Run [[yellow]soon[/]]\t\t───>  Run program and make custom exploit [[cyan] via GDB API[/] ] [/]
	[b][[red]4[/]] exit or q\t\t───>  to quit. [/]
	
	'''
	pressToBack = ''
	if c:
		with open('Texploit.py', 'w+') as f:
			f.write(c)
		info = ''
		pressToBack = '[b][blue] Press enter to back into menu page[/][/]'
		layout['app'].update(Panel(Syntax.from_path("Texploit.py"),title="[red][b]AutoPwn mode .[/][/]", subtitle=pressToBack))
	else:
		layout['app'].update(Panel(info,title="", subtitle=pressToBack))
	

def main(elf):
	while True:
		try:		
			print(layout)
			menu = input('Enter :').strip()
			layout['side'].visible = True
			if menu.lower() == 'autopwn' or menu == '1':
				app(elf,Autopwn(elf.file.name))
				print(layout)
			elif menu.lower == 'run' or menu == '3':
				pass # soon
			elif menu.lower() == 'exit' or menu.lower() == 'q' or menu == '4':
				print('- Good luck')
				subprocess.run(['rm', 'TruePwn_Disasm_main'])
				exit()
			else:
				app(elf,'')
			try:
				if menu.lower()[0:3] == 'dis' or menu[0] == '2':
					func = menu.split(' ')[-1]
					disas(elf, func)
			
			except:
				pass

		except KeyboardInterrupt:
			print('- Good luck')
			subprocess.run(['rm', 'TruePwn_Disasm_main'])
			exit()
		

if __name__ == '__main__':
	try:
		sys.argv[1]
	except IndexError:
		print('- python3 TruePwn.py [red]./test.out[/]')
		exit()
	elf = ELF(sys.argv[1])
	Style_(elf)
	app(elf,"")
	main(elf)