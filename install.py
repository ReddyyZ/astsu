import platform,os

machine_os = platform.system()

if machine_os == 'Linux':
    os.system('mkdir /usr/share/astsu')
    os.system('cp * /usr/share/astsu')
    os.system('mv /usr/share/astsu/astsu.py /usr/share/astsu/astsu')
    os.system('ln -s /usr/share/astsu/astsu /usr/bin/astsu')
    print('[+] ASTSU installed')
elif machine_os == 'Windows':
    os.system('mkdir C:\\astsu')
    os.system('copy * C:\\astsu')
    os.system('rename C:\\astsu\\astsu.py C:\\astsu\\astsu')
    print('[+] ASTSU installed')
else:
    print('[-] Not founded the os')