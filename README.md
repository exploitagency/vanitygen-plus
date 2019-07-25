-----
Vanitygen PEPE
-----

./vanitygen -C PEPE PAddress 

## Example:
```
./vanitygen -C PEPE PEN1S 

Generating PEPE / MEME Address
Difficulty: 4553521
PEPE Pattern: PEN1S                                                            
PEPE Address: PEN1SsgFNTNFyZu2qAn26ivyBE23M6wfX7
PEPE Privkey: 6A7jyhqsAH463iPY6JmWv8YVesW7aYshrcqvgjB7oQ55V7i3UeF
```


## Compile

```
sudo apt install libpcre++-dev gcc
git clone https://github.com/cryptopepe/vanitygen-pepe
cd vanitygen-pepe
make
```

----------------------------------------------

**For generating addresses using the CPU(slower) use: vanitygen !**  
**For generating addresses using the GPU(faster) use: oclvanitygen !**  

**NOTES:**	All arguments are case sensitive!  
	Address prefix must be at the end of the command.  
	oclvanitygen requires OpenCL and correct drivers.  

 * `-C PEPE` : Generate address for PEPE/MEME coin  
 * `-o results.txt` : saves the matches to results.txt  
 * `-i` : case-Insensitive(do not add this flag to match exact case)  
 * `-k` : keep going even after match is found(do not add this flag to stop after the first match)  
 * PEPEADDRESS : the address you are searching for

Example output of above command:  
>Generating PEPE Address  
>Difficulty: 4553521  
>PEPE Pattern: PAddress
>PEPE Address: PAddressT6jSVcid5MQAJBrGUR6MLDpdyb8oiQ  
>PEPE Privkey: wrRxctq3f7A1zkpyWoZRifRk5eAC2UM9idh83SPLhz6gAFfqdL  


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
Linux: `./keyconv -C PEPE -d yTYFUWAsgFmMxCbKtu3RdrrJXosZrjxiQFA2o43neB4jPpfLe5owNNrteTs8mpvua8Ge`  
Windows: `keyconv.exe -C PEPE -d yTYFUWAsgFmMxCbKtu3RdrrJXosZrjxiQFA2o43neB4jPpfLe5owNNrteTs8mpvua8Ge`  

 * `-C AC` Specifies PepeCoin  
 * `-d` means decrypt the protected key of "yTYFUWAsgFmMxCbKtu3RdrrJXosZrjxiQFA2o43neB4jPpfLe5owNNrteTs8mpvua8Ge"  

>Enter import password:  --- Enter "password" or whatever you specified as password and press enter  
>Address: Aa853vQs6QGrTuTHb7Q45tbeB8n4EL47vd  
>Privkey: 66GRP2W5H4sWbgrBRAuPc3qZxUtP5boubJ9N2M5wZio6fhWjzbr  
