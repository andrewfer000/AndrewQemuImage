# AndrewQemuImage
My custom QEMU image builder using python and packer. Work in progress!

# Setup
1. Ensure QEMU KVM is installed and Libvirtd is running (VMware runner comming soon!)
2. Make sure the packer executible is in the parent directory and is executable
3. Have python 3.9+ installed with the required modules

# Use
As of right now you can only use this on Linux systems with QEMU. A VMware genarator is comming soon!

First you need to generate a config file. `python3 generate-config.py --help` will give you the options you need to set to build an OS. If no options are set a default configuration will be generated.
Once a configuration (setup.json) is generated. Run `python3 LinuxAutomated.py` and if everything is setup properly watch it go! 

# End Result
Once your image is generated it will be in the folder is OSname.qcow2 you can then rename it and install it in QEMU. Please note at the moment the OS has a custom DHCP service installed in order for DHCP to work after installation. This will be toggleable in the future if you use a static IP address.
