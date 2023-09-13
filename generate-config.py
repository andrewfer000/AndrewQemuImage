from jinja2 import Environment, FileSystemLoader
from urllib.parse import urlparse
import subprocess, signal, sys, threading, time, os, argparse
from getpass import getpass

def generate_hashed_password(password):
    try:
        output = subprocess.check_output(['mkpasswd', '-m', 'sha-512', password], universal_newlines=True)
        sha512_password = output.strip()
        return sha512_password
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return None

def read_public_ssh_key(file_path):
    try:
        with open(file_path, 'r') as ssh_key_file:
            public_key = ssh_key_file.read()
            print(f"Home Directory Public Key extraction success!")
            return public_key
    except FileNotFoundError:
        print(f"WARNING: SSH key file not found: {file_path}. Using Developer placeholder")
        return "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCSE6eTrc91qB5/EWp/8VH7uk6c2fDo3uT7PPEiRtjInIIRajaZK4yLBegLEKC15Vhvwtx04URFxl7md/2wTSnMAc+yluBBpXE19KxjXmp0m2WqtstFit0IxCVtWeA3cm+EOBpoRHN7cAi0e9q+oXNGGkORfbsl/yKDyT0aS2Gko8f9ED8L3FyQ4g2UX6vlxM3T9BEZBrdPhHPsEqD4RM5RADe/M9eX8ERUb/+g3SMXTNirYPru43e6kVTXRQi8Bs1Qr/MnLzyfHEhf++RLZYHDfrP+sN/19zZOAG0Vj5+1WN9SFmsFY+yG/MYRm6+Rv4WZrBlDiYce/wupxL8Y1jSfCI98joWL2pbHwgTEuNWnQBaJWctqpmh/RohNMvVThzTZeZP4g/rle8ymisErjVc9Ug+8yd/000VotBdowaLUDYGp7NBSGuE5yknvZkKzlBZlOec2BhQaSsValnnJVKZRAPWpLZgaHtLSSY4KFqMf43ePqDTownwMpVl3TGJCWIM= owner@andrews-asus"

def interactive_mode():
    print("Welcome to interactive mode! NOT IMPLEMENTED")
    exit()

def main():
    vm_network = ""
    os_username = ""
    os_password = ""
    domain = ""
    os_proxy = ""
    disk_space = ""
    os_hostname = ""
    vm_cpu_cores = ""
    ssh_key_manual = ""
    ip_addr = ""
    ssh_key_url = ""
    is_cloud = True
    os_name = ""
    os_version = ""
    vm_name = ""
    os_dhcp = True
    memory = ""
    output_file = ""
    role = ""
    os_mirror = ""

    env = Environment(loader=FileSystemLoader('.'))
    setup_template = env.get_template('templates/setup.json.j2')
    parser = argparse.ArgumentParser(description="Program to process command-line arguments.")

    # Add command-line arguments for os_name and os_version
    parser.add_argument("-i", "--interactive", action="store_true", help="Enter interactive mode")
    parser.add_argument("-n", "--vm_name", type=str, help="Specify the VM name.")
    parser.add_argument("-O", "--os_name", type=str, help="Specify the OS name.")
    parser.add_argument("-V", "--os_version", type=str, help="Specify the OS version. (i.e. 12.1 for Debian 12.1)")
    parser.add_argument("-l", "--is_cloud", action="store_true", help="Specify if the VM is local or Cloud.")
    parser.add_argument("-s", "--ssh_key_url", type=str, help="Specify the link to your SSH key. I.e. http://example.com:80/my-ssh-key.txt")
    parser.add_argument("-I", "--ip_addr", type=str, help="Specify a static IP settings if needed. In the format of IP/Subnet, Gateway. For example 192.168.122.5/24, 192.168.122.1")
    parser.add_argument("-S", "--ssh_key_manual", type=str, help="Insert your public SSH key here. It will be served at localhost and to the VM at 10.0.2.2:8576/public_key.txt")
    parser.add_argument("-c", "--cpu_cores", type=str, help="Specify the CPU cores")
    parser.add_argument("-M", "--memory", type=str, help="Specify the VM's memory")
    parser.add_argument("-d", "--vm_disk_space", type=str, help="Specify the VM's disk space.")
    parser.add_argument("-H", "--hostname", type=str, help="Specify the OS hostname.")
    parser.add_argument("-D", "--domain", type=str, help="Specify the OS domain.")
    parser.add_argument("-p", "--os_proxy", type=str, help="Specify a proxy. I.e. http://proxyip:port")
    parser.add_argument("-N", "--os_username", type=str, help="Specify the OS non-root user")
    parser.add_argument("-P", "--os_password", type=str, help="Specify the users password. If none is specified you will be promted for one.")
    parser.add_argument("-v", "--vm_network", type=str, help="Specify the VM network.")
    parser.add_argument("-b", "--build_now", action="store_true", help="Triggers the VM to build")
    parser.add_argument("-B", "--build_deploy", action="store_true", help="Builds and Deploys the VM to your local machine using Libvirt")
    parser.add_argument("-Q", "--hypervisor", type=str, help="Specify the target hypervisor. I.e 'libvirt' for qemu/kvm, 'vmware' for VMware.")
    parser.add_argument("-J", "--os_checksum", type=str, help="Specify the OS ISO's checksum")
    parser.add_argument("-L", "--os_download", type=str, help="Specify the OS image to download.")
    parser.add_argument("-W", "--webserver_port", type=str, help="Specify the port to run the local webserver. Default is 8576")
    parser.add_argument("-K", "--headless", action="store_true", help="Do not display VM durring build")
    parser.add_argument("-o", "--output_file", type=str, help="Specify the JSON file to output to. Default is setup.json")
    parser.add_argument("-r", "--role", type=str, help="Specify a role for the server. This will run an Ansible playbook")
    parser.add_argument("-U", "--show_details", action="store_true", help="Choose to show details if needed. If not set then no text output will be shown apon setup generation.")


    args = parser.parse_args()

    if args.interactive:
        print ("Load Interactive Mode")
        interactive_mode(vm_network, os_username, os_password, domain, os_proxy, disk_space, os_hostname, vm_cpu_cores, ssh_key_manual, ip_addr, ssh_key_url, is_cloud, os_name, os_version, vm_name, os_dhcp, memory)
    else:
        pass

    if args.build_now:
        print ("Building the OS's drive")
    else:
        pass

    if args.build_deploy:
        print ("Building and Deploying on the selected hypervisor!")
    else:
        pass

    if args.hypervisor:
        hypervisor = args.hypervisor
    else:
        hypervisor = "qemu"

    if args.role:
        role = args.role
    else:
        role = "None"

    if args.output_file:
        output_file = args.output_file
    else:
        output_file = "setup.json"

    if args.webserver_port:
        webserver_port = args.webserver_port
    else:
        webserver_port = "8576"

    if args.os_checksum:
        os_checksum = args.os_checksum
    elif args.os_name == "Rocky" and args.os_version == "9.2":
        os_checksum = "sha256:06505828e8d5d052b477af5ce62e50b938021f5c28142a327d4d5c075f0670dc"
    elif args.os_name == "Alma" and args.os_version == "9.2":
        os_checksum = "sha256:f501de55f92e59a3fcf4ad252fdfc4e02ee2ad013d2e1ec818bb38052bcb3c32"
    elif args.os_name == "Debian" and args.os_version == "12.1":
        os_checksum = "sha256:9f181ae12b25840a508786b1756c6352a0e58484998669288c4eec2ab16b8559"
    else:
        os_checksum = "sha256:9f181ae12b25840a508786b1756c6352a0e58484998669288c4eec2ab16b8559"
        print(f"WARNING: OS Name and/or Version not supported for auto-download Defaulting to Debian 12.1")

    if args.os_download:
        os_download = args.os_download
    elif args.os_name == "Rocky" and args.os_version == "9.2":
        os_download = "https://download.rockylinux.org/pub/rocky/9.2/isos/x86_64/Rocky-9.2-x86_64-minimal.iso"
        os_mirror = "https://mirror.xenyth.net/rocky/9.2/BaseOS/x86_64/os/"
    elif args.os_name == "Alma" and args.os_version == "9.2":
        os_download = "http://mirror.cs.pitt.edu/almalinux/9.2/isos/x86_64/AlmaLinux-9-latest-x86_64-boot.iso"
        os_mirror = "https://mirror.xenyth.net/almalinux/9.2/BaseOS/x86_64/os/"
    elif  args.os_name == "Debian" and args.os_version == "12.1":
        os_download = "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.1.0-amd64-netinst.iso"
    else:
       print(f"WARNING: OS Name and/or Version not supported for auto-download Defaulting to Debian 12.1")
       os_download = "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.1.0-amd64-netinst.iso"

    if args.memory:
        memory = args.memory
    else:
        memory = "1024M"

    if args.vm_network:
        vm_network = args.vm_network
    else:
        vm_network = "NA"

    if args.os_username:
        os_username = args.os_username
    else:
        os_username = "owner"
        print(f"No user specified. Using owner")

    if args.os_password:
        os_password = args.os_password
        os_password_hashed = generate_hashed_password(os_password)
    else:
        os_password = getpass("A Password is REQUIRED: ")
        os_password_hashed = generate_hashed_password(os_password)

    if args.domain:
        os_domain = args.domain
    else:
        os_domain = "example.com"

    if args.os_proxy:
        os_proxy = args.os_proxy
    else:
        os_proxy = "NA"

    if args.vm_disk_space:
        vm_disk_space = args.vm_disk_space
    else:
        vm_disk_space = "42G"

    if args.hostname:
        os_hostname = args.hostname
    else:
        os_hostname = "default"

    if args.cpu_cores:
        vm_cpu_cores = args.cpu_cores
    else:
        vm_cpu_cores = "2"

    if args.ssh_key_manual:
        ssh_key_manual = args.ssh_key_manual
    else:
        print("No manual key specified. Attempting to use id_rsa.pub in your home directory")
        home_dir = os.path.expanduser("~")
        ssh_key_path = os.path.join(home_dir, '.ssh', 'id_rsa.pub')
        ssh_key_manual = read_public_ssh_key(ssh_key_path)
        ssh_key_manual = ssh_key_manual.strip(f"\n")

    if args.ip_addr:
        ip_addr = args.ip_addr
        os_dhcp = False
    else:
         ip_addr = "USEDHCP"
         os_dhcp = True

    if args.ssh_key_url:
        ssh_key_url = args.ssh_key_url
    else:
        ssh_key_url = "USEMANUAL"
        if not args.ssh_key_manual:
            print(f"WARNING: No SSH URL specified AND no manual SSH key specified. If automatic key extraction failed the Developer placeholder will be used. Use -S 'MyPublicKey' to manually configure a key.")

    if args.is_cloud:
        is_cloud = args.is_cloud
    else:
         is_cloud = False

    if args.headless:
        headless = args.headless
    else:
         headless = False

    if args.os_name:
        os_name = args.os_name
    else:
        os_name = "Debian"

    if args.os_version:
        os_version = args.os_version
    else:
        os_version = "12.1"

    if args.vm_name:
        vm_name = args.vm_name
    else:
         vm_name= "Default"

    if args.show_details:
        print(f" \n Configured Settings: \n VM Network: {vm_network} \n Username: {os_username} \n Password: {os_password} \n Domain: {os_domain} \n Proxy: {os_proxy} \n Disk Space: {vm_disk_space} \n Hostname: {os_hostname} \n CPU Cores: {vm_cpu_cores} \n Manual SSH Key: {ssh_key_manual} \n IP Settings: {ip_addr} \n SSH Key File: {ssh_key_url} \n Is Cloud: {is_cloud} \n OS: {os_name} \n OS Version: {os_version} \n VM Name: {vm_name} \n Memory: {memory} \n OS Download: {os_download} \n OS checksum: {os_checksum} \n Webserver Port {webserver_port} \n Headless: {headless} \n OS Mirror: {os_mirror}")
    else:
        print(f"\n\nSetup generated successfully!\n\n")


    rendered_setup = setup_template.render(vm_network=vm_network, os_username=os_username, os_password=os_password, domain=os_domain, os_proxy=os_proxy, disk_space=vm_disk_space, os_hostname=os_hostname, vm_cpu_cores=vm_cpu_cores, ssh_key_manual=ssh_key_manual, ip_addr=ip_addr, ssh_key_url=ssh_key_url, is_cloud=is_cloud, os_name=os_name, os_version=os_version, vm_name=vm_name, os_dhcp=os_dhcp, os_password_hashed=os_password_hashed, memory=memory,  os_checksum=os_checksum, os_download=os_download, webserver_port=webserver_port, headless=headless, os_mirror=os_mirror)

    with open(output_file, 'w') as f:
        f.write(rendered_setup)

    print(f" \n VM Build Config file has been generated! You can now build your VM")

if __name__ == "__main__":
    main()
