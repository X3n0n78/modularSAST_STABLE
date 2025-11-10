# Ez egy másik sebezhető fájl
import subprocess

def run_command(cmd):
    # Az exec() egy újabb komoly veszélyforrás
    exec(f"print('Parancs futtatása: {cmd}')")