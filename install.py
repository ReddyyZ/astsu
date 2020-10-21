import platform,os

machine_os = platform.system()

if machine_os == 'Linux':
    os.system('mkdir /usr/share/astsu')
    os.system('cp -r * /usr/share/astsu')
    os.system('ln -s /usr/share/astsu/astsu.py /usr/bin/astsu')
    print('[+] ASTSU installed')
elif machine_os == 'Windows':
    os.system("mkdir C:\\astsu")
    os.system("copy * C:\\astsu")
    os.system("mkdir C:\\astsu\\modules")
    os.system("copy modules C:\\astsu\\modules\\")
    os.system("echo @echo off > C:\\Windows\\System32\\astsu.bat")
    os.system("echo python3 C:\\astsu\\astsu.py %* >> C:\\Windows\\System32\\astsu.bat")
    print('\n[+] ASTSU installed\n')
else:
    print('[-] Not founded the os')
