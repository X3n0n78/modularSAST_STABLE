import subprocess

def vulnerable_call(command):
    # EZ VESZÉLYES: shell=True parancsinjektálást tesz lehetővé
    subprocess.run(f"echo {command}", shell=True)

def safe_call(command):
    # EZ BIZTONSÁGOS: a 'shell=False' az alapértelmezett, és a parancsot
    # argumentumlistaként kezeli.
    subprocess.run(["echo", command])

def vulnerable_popen(command):
    # A Popen-re ugyanúgy érvényes
    subprocess.Popen(command, shell=True)