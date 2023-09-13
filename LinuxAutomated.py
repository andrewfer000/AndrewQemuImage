from jinja2 import Environment, FileSystemLoader
from urllib.parse import urlparse
from getpass import getpass
import subprocess, signal, sys, threading, http.server, socketserver, hashlib, time, datetime, os, json, argparse, shutil

def break_up_url(url):
    parsed_url = urlparse(url)
    return {
        "scheme": parsed_url.scheme,
        "hostname": parsed_url.hostname,
        "port": parsed_url.port,
        "path": parsed_url.path
        }

def write_file(filename, content):
    with open(filename, 'w') as file:
        file.write(content)

def delete_file(file_path):
    try:
        os.remove(file_path)
        print(f"File '{file_path}' deleted successfully.")
    except OSError as e:
        print(f"Error deleting the file '{file_path}': {e}")

def run_program(command, command2):
    process = subprocess.Popen(command, shell=True)
    process2 = subprocess.Popen(command2, shell=True)
    process.wait()

    if process.returncode == 0 or process.returncode == 1:
        process2.terminate()

    try:
        process.wait()
    except KeyboardInterrupt:
        process.send_signal(signal.SIGINT)
        process2.terminate()
        process.wait()

def main():
    current_datetime = datetime.datetime.now()
    formatted_datetime = current_datetime.strftime("%y%m%d%H%M%S")
    parser = argparse.ArgumentParser(description="Builds your OS based on the config file.")
    parser.add_argument("-i", "--input_file", type=str, help="Specify the setup.json file generated by generate-config. Default is setup.json")
    args = parser.parse_args()


    if args.input_file:
        input_file = args.input_file
    else:
        input_file = "setup.json"

    try:
        with open(input_file, "r") as file:
            setup = json.load(file)
    except (FileNotFoundError, UnboundLocalError) as e:
        print("**ERROR** Default setup file not found or custom setup file not found. Run generate-config.py with your options to build a config.")
        exit()

    if setup:
        vm_name = setup["vm_name"]
        vm_os = setup["vm_os"]
        vm_os_version = setup["vm_os_version"]
        vm_is_cloud = setup["vm_is_cloud"]
        vm_static_ip = setup["vm_static_ip"]
        vm_sshkey_url = setup["vm_sshkey_url"]
        vm_sshkey_manual = setup["vm_sshkey_manual"]
        domain = setup["domain"]
        vm_cpu_cores = setup["vm_options"]["vm_cpu_cores"]
        vm_memory = setup["vm_options"]["vm_memory"]
        vm_disk_space = setup["vm_options"]["vm_disk_space"]
        vm_network = setup["vm_options"]["vm_network"]
        os_download = setup["os_options"]["os_download"]
        os_checksum = setup["os_options"]["os_checksum"]
        os_username = setup["os_options"]["os_username"]
        os_password =  setup["os_options"]["os_password"]
        os_hashed_password =  setup["os_options"]["os_hashed_password"]
        os_hostname = setup["os_options"]["os_hostname"]
        os_dhcp = setup["os_options"]["os_dhcp"]
        os_proxy = setup["os_options"]["os_proxy"]
        os_mirror = setup["os_options"]["os_mirror"]
        webserver_port = setup["webserver_port"]
        headless = setup["headless"]
        new_filename = f"{vm_os}-{vm_os_version}-{formatted_datetime}.qcow2"

        #print("Lol:")
        #for Lol in Lols:
        #    print(f"  {Lol}")
    else:
        print(f"ERROR: No setup file found! Exiting.")
        exit()

    httpaddr = "10.0.2.2"
    env = Environment(loader=FileSystemLoader('.'))

    if vm_sshkey_url == "USEMANUAL":
        print("Inserting manual SSH key into http/public-key.txt")
        write_file("http/public-key.txt", vm_sshkey_manual)
        vm_sshkey_url = f"http://10.0.2.2:{webserver_port}/public-key.txt"
    else:
         print(f"Using SSH Key located at: {vm_sshkey_url}")

    ssh_url_parts = break_up_url(vm_sshkey_url)
    fsshkeyurl = f"{ssh_url_parts['scheme']}://{ssh_url_parts['hostname']}"
    fsshkeyport = f"{ssh_url_parts['port']}"
    fsshkeyfile = f"{ssh_url_parts['path']}"

    if vm_os == "Debian":
        pressed_template = env.get_template('templates/debian12_preseed.cfg.j2')
        packer_template = env.get_template('templates/debian-packer.json.j2')

        rendered_preseed = pressed_template.render(username=os_username, hashed_password=os_hashed_password, os_hostname=os_hostname, domain=domain)

        rendered_packer = packer_template.render(username=os_username, password=os_password, sshkeyurl=fsshkeyurl, sshkeyport=fsshkeyport, sshkeyfile=fsshkeyfile, iso_url=os_download, iso_checksum=os_checksum, disk_size=vm_disk_space, httpaddr=httpaddr, httpport=webserver_port, headless=headless, vm_memory=vm_memory, vm_cpu_cores=vm_cpu_cores)

        output_packer = 'mydebian.json'
        with open(output_packer, 'w') as f:
            f.write(rendered_packer)

        output_preseed = 'http/debian12_preseed.cfg'
        with open(output_preseed, 'w') as f:
            f.write(rendered_preseed)

        source_file = "output-debian/packer-qemu"
        destination_dir = os.path.dirname(os.path.dirname(source_file))

    elif vm_os == "Rocky" or vm_os == "Alma":
        pressed_template = env.get_template('templates/ksconfig.cfg.j2')
        packer_template = env.get_template('templates/rocky-packer.json.j2')

        rendered_preseed = pressed_template.render(username=os_username, hashed_password=os_hashed_password, os_hostname=os_hostname, domain=domain, os_mirror=os_mirror)

        rendered_packer = packer_template.render(username=os_username, password=os_password, sshkeyurl=fsshkeyurl, sshkeyport=fsshkeyport, sshkeyfile=fsshkeyfile, iso_url=os_download, iso_checksum=os_checksum, disk_size=vm_disk_space, httpaddr=httpaddr, httpport=webserver_port, headless=headless, vm_memory=vm_memory, vm_cpu_cores=vm_cpu_cores)

        output_packer = 'myrocky.json'
        with open(output_packer, 'w') as f:
            f.write(rendered_packer)

        output_preseed = 'http/ksconfig.cfg'
        with open(output_preseed, 'w') as f:
            f.write(rendered_preseed)

        source_file = "output-rocky/packer-qemu"
    else:
        print("OS is not supported or specified in the setup config. Exiting")
        exit()


    # Create the threads for the server and packer
    program1_command = f"../packer build {output_packer}"
    program2_command = "cd http && python3 fileserver.py"
    program1_thread = threading.Thread(target=run_program, args=(program1_command,  program2_command))
    program1_thread.daemon = True
    program1_thread.start()

    try:
        while program1_thread.is_alive():
            pass
    except KeyboardInterrupt:
        print("\nStopping the server and program...")
        program1_thread.join()
        print("Server and program stopped.")

    program1_thread.join()
    if not program1_thread.is_alive():
        print("Cleaning up.")
        delete_file(output_preseed)
        delete_file(output_packer)
        if source_file:
            destination_dir = os.path.dirname(os.path.dirname(source_file))
            new_file_path = os.path.join(destination_dir, new_filename)
            shutil.move(source_file, new_file_path)
            old_dir = os.path.dirname(source_file)
            shutil.rmtree(old_dir)
            print(f"OS filename is {new_filename}")

        if vm_sshkey_url == f"http://10.0.2.2:{webserver_port}/public-key.txt":
            delete_file("http/public-key.txt")

if __name__ == "__main__":
    main()