-----
Vanitygen PLUS!  
-----

** This is released only as source code. You need to compile it yourself. **  

**WARNING!** This program has not been thoroughly tested. Please attempt importing an address first into a running node.  Send a tiny amount you don't mind losing to the address. Then perform a test spend. I will not be held liable for lost funds as a result of the use of this program. You are responsible for your use of this open source software.

Be sure to report any issues or bugs and fixes, I am happy to accept pull requests! If you have an altcoin you would like to add please let me know.  

-----
Getting Started  
-----  
**Download the code and build with make**

After compiling, run it like:

Running On Linux: `./vanitygen -ARGS`, or `./oclvanitygen -ARGS`, `./keyconv -ARGS`, etc  
Running On Windows: `vanitygen.exe -ARGS`, `oclvanitygen.exe -ARGS`, `keyconv.exe -ARGS`, etc  

**For generating addresses using the CPU(slower) use: vanitygen **  
**For generating addresses using the GPU(faster) use: oclvanitygen **  

**NOTES:**	All arguments are case sensitive!  
	Address prefix must be at the end of the command.  
	oclvanitygen requires OpenCL and correct drivers. This software works well on mining rigs.

**Get a list of the supported Coins with:**  
Linux CPU: `./vanitygen -C LIST`  
Linux GPU: `./oclvanitygen -C LIST`  
Windows CPU: `vanitygen.exe -C LIST`  
Windows GPU: `oclvanitygen.exe -C LIST`  

A list of all the supported crypto coins will be output.  

Choose your coin from the list noting the ARGUMENT needed for the coin located in the left hand column.  
For Ritocoin it is RITO. For Bitcoin it is BTC.  Etc...  

**Now lets generate a RITO address with the prefix "BFoo":**  
Linux CPU: `./vanitygen -C RITO -o results.txt -i -k BFoo`  
Linux GPU: `./oclvanitygen -C RITO -o results.txt -i -k BFoo`  
Windows CPU: `vanitygen.exe -C RITO -o results.txt -i -k BFoo`  
Windows GPU: `oclvanitygen.exe -C RITO -o results.txt -i -k BFoo`  

 * `-C RITO` : Chooses the RITO coin  
 * `-o results.txt` : saves the matches to results.txt  
 * `-i` : case-Insensitive(do not add this flag to match exact case)  
 * `-k` : keep going even after match is found(do not add this flag to stop after the first match)  
 * `BFoo` : the address you are searching for (RITO addresses start with "B")  

Example output of above command:  

>Generating RITO Address  

>Difficulty: 4553521  

>RITO Address: BFoo4XJNzKk2CZW2cJZ6nP9ncVNvdQrp8V

>RITO Privkey: 5gKsgY4Bf7cbqZtW2CX1Lxy5j99oRa6YBT7TQDj7AuJCPAAb9FW

**If you have dependency errors on Linux or need instructions for compiling from source(Kaling Rolling/Linux) see link below:**  
https://legacysecuritygroup.com/index.php/projects/recent/12-software/35-oclvanitygen-compiling-and-use  

------  
Fix libcrypto.so.1.0.2 error(Debian, Ubuntu)  
------  
Error:
>./vanitygen: error while loading shared libraries: libcrypto.so.1.0.2: cannot open shared object file: No such file or directory  

Fix it by issuing the below commands, in turn either installing or downgrading libcrypto.  The error comes from an incompatibility with the newer version of libcrypto.  Most older projects have this same bug.  
```
wget http://ftp.us.debian.org/debian/pool/main/g/glibc/libc6-udeb_2.24-11+deb9u3_amd64.udeb
dpkg -i libc6-udeb_2.24-11+deb9u3_amd64.udeb
wget http://ftp.us.debian.org/debian/pool/main/o/openssl1.0/libcrypto1.0.2-udeb_1.0.2l-2+deb9u3_amd64.udeb
dpkg -i libcrypto1.0.2-udeb_1.0.2l-2+deb9u3_amd64.udeb
rm libc6-udeb_2.24-11+deb9u3_amd64.udeb && rm libcrypto1.0.2-udeb_1.0.2l-2+deb9u3_amd64.udeb 
```
-----
Encrypting and Decrypting a vanitygen or oclvanitygen private key  
-----  
**Encrypting generated private key:**  
Linux: `./vanitygen -E password -C AC Aa`  
Windows: `./vanitygen -E password -C AC Aa`  
*For GPU use "oclvanitygen" in place of "vanitygen"*  

 * `-C AC Aa` Choose AsiaCoin and address prefix "Aa"  
 * `-E password` Encrypt key with password as "password",  
**NOTE:** It is more secure to use option `-e` with no trailing password,  
then vanitygen prompts for a password so theres no command history.  
Also please choose a stronger password than "password".  

>Generating AC Address  
>Difficulty: 23   
>AC Pattern: Aa                                                                      
>AC Address: Aa853vQs6QGrTuTHb7Q45tbeB8n4EL47vd  
>AC Protkey: yTYFUWAsgFmMxCbKtu3RdrrJXosZrjxiQFA2o43neB4jPpfLe5owNNrteTs8mpvua8Ge  

**Decrypting generated ProtKey with Keyconv:**  
Linux: `./keyconv -C AC -d yTYFUWAsgFmMxCbKtu3RdrrJXosZrjxiQFA2o43neB4jPpfLe5owNNrteTs8mpvua8Ge`  
Windows: `keyconv.exe -C AC -d yTYFUWAsgFmMxCbKtu3RdrrJXosZrjxiQFA2o43neB4jPpfLe5owNNrteTs8mpvua8Ge`  

 * `-C AC` Specifies AsiaCoin  
 * `-d` means decrypt the protected key of "yTYFUWAsgFmMxCbKtu3RdrrJXosZrjxiQFA2o43neB4jPpfLe5owNNrteTs8mpvua8Ge"  

>Enter import password:  --- Enter "password" or whatever you specified as password and press enter  
>Address: Aa853vQs6QGrTuTHb7Q45tbeB8n4EL47vd  
>Privkey: 66GRP2W5H4sWbgrBRAuPc3qZxUtP5boubJ9N2M5wZio6fhWjzbr  

