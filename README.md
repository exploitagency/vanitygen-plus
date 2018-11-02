-----
Vanitygen PLUS!  
-----

**Download the latest binary from: https://github.com/exploitagency/vanitygen-plus/releases !**  

Note: For generating a Zcash or Zclassic address please see the Z repo: https://github.com/exploitagency/vanitygen_z

Forked from samr7/vanitygen ,  
then modified by Corey Harding  
to support various Alt-Coins,  
and with the following changes:  

 + Generate vanity addresses for 80+ coins! with mods by Corey Harding  
 + I also removed the prefix length limit to search for longer addresses.   
 + Manually merge changes from: cryptapus For -Y privkey values  
 + Manually merge changes from: elichai For keyconv decrypt  
 + Manually merge changes from: salfter For compressed key support  
 + Manually merge changes from: WyseNynja For oclvanityminer updates  
 + Manually merge changes from: Rytiss For Initialize bn_zero to allow Intel CPU OpenCL compilation  
 + Manually merge changes from: fizzisist For Document -P option  
 + Manually merge changes from: bitkevin For fix hd 68/69xx, 7xxx   
 + Manually merge changes from: wolf9466 For Groestlcoin address support  

**WARNING!** This program has not been thoroughly tested.  Please attempt importing an address first.  
Send a tiny amount you don't mind losing to the address.  Then perform a test spend.  
I will not be held liable for lost funds as a result of the use of this program.  
Also do not use this program for nefarious purposes!  I do not condone illegal activity.  
The chances of actually brute forcing an address is nearly impossible anyways.  

Be sure to report any issues or bugs and fixes, I am happy to accept pull requests!  
If you have an altcoin you would like to add please let me know.  

-----
Getting Started  
-----  
**Download the latest binary from: https://github.com/exploitagency/vanitygen-plus/releases !**  
Linux Binary (Compiled on 64bit Debian Testing)  
Windows Binary (Compiled on Win10 64bit)  

Extract the files,  
open a terminal/command prompt,  
change to directory containing vanitygen-plus binaries.  

Running On Linux: `./vanitygen -ARGS`, or `./oclvanitygen -ARGS`, `./keyconv -ARGS`, etc  
Running On Windows: `vanitygen.exe -ARGS`, `oclvanitygen.exe -ARGS`, `keyconv.exe -ARGS`, etc  

**For generating addresses using the CPU(slower) use: vanitygen !**  
**For generating addresses using the GPU(faster) use: oclvanitygen !**  

**NOTES:**	All arguments are case sensitive!  
	Address prefix must be at the end of the command.  
	oclvanitygen requires OpenCL and correct drivers.  

**Get a list of the supported Coins with:**  
Linux CPU: `./vanitygen -C LIST`  
Linux GPU: `./oclvanitygen -C LIST`  
Windows CPU: `vanitygen.exe -C LIST`  
Windows GPU: `oclvanitygen.exe -C LIST`  

A list of all the supported crypto coins will be output.  

Choose your coin from the list noting the ARGUMENT needed for the coin located in the left hand column.  
For LBRY it is simply LBRY.  For Bitcoin it is BTC.  Etc...  

**Now lets generate a LBRY address with the prefix "bTEST":**  
Linux CPU: `./vanitygen -C LBRY -o results.txt -i -k bTEST`  
Linux GPU: `./oclvanitygen -C LBRY -o results.txt -i -k bTEST`  
Windows CPU: `vanitygen.exe -C LBRY -o results.txt -i -k bTEST`  
Windows GPU: `oclvanitygen.exe -C LBRY -o results.txt -i -k bTEST`  

 * `-C LBRY` : Chooses the LBRY coin  
 * `-o results.txt` : saves the matches to results.txt  
 * `-i` : case-Insensitive(do not add this flag to match exact case)  
 * `-k` : keep going even after match is found(do not add this flag to stop after the first match)  
 * `bTEST` : the address you are searching for(LBRY addresses start with "b")  

Example output of above command:  
>Generating LBRY Address  
>Difficulty: 4553521  
>LBRY Pattern: bTEST                                                                   
>LBRY Address: bTEST6jSVcid5MQAJBrGUR6MLDpdyb8oiQ  
>LBRY Privkey: wrRxctq3f7A1zkpyWoZRifRk5eAC2UM9idh83SPLhz6gAFfqdL  

**If you have dependency errors on Linux  
or need instructions for compiling from source(Kaling Rolling/Linux) see link below:**  
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

Current List of Available Coins for Address Generation  
-----
|**Argument(UPPERCASE)** | **Coin** | **Address Prefix**  |
| --------------------------------------- | -------------------------------------------- | ------------ |
|42 | 42coin | 4  |
|AC | Asiacoin | A  |
|ACM | Actinium | N |
|AIB | Advanced Internet Block by IOBOND | A  |
|ANC | Anoncoin | A  |
|ARS | Arkstone | A  |
|ATMOS | Atmos | N  |
|AUR | Auroracoin | A  |
|AXE | Axe | P |
|BLAST | BLAST | B  |
|BLK | Blackcoin | B  |
|BWK | Bulwark | b  |
|BQC | BBQcoin | b  |
|BTC | Bitcoin | 1  |
|TEST | Bitcoin Testnet | m or n  |
|BTCD | Bitcoin Dark | R  |
|CARE | Carebit | C  |
|CCC | Chococoin | 7  |
|CCN | Cannacoin | C  |
|CDN | Canadaecoin | C  |
|CLAM | Clamcoin | x  |
|CNC | Chinacoin | C  |
|CNOTE | C-Note | C |
|CON | PayCon | P  |
|CRW | Crown | 1  |
|DASH | Dash | X  |
|DEEPONION | DeepOnion | D  |
|DNR | Denarius | D  |
|DGB | Digibyte | D  |
|DGC | Digitalcoin | D  |
|DMD | Diamond | d  |
|DOGED | Doge Dark Coin | D  |
|DOGE | Dogecoin | D  |
|DOPE | Dopecoin | 4  |
|DVC | Devcoin | 1  |
|EFL | Electronic-Gulden-Foundation | L  |
|EMC | Emercoin | E  |
|EXCL | Exclusivecoin | E  |
|FAIR | Faircoin2 | f  |
|FLOZ | FLOZ | F  |
|FTC | Feathercoin | 6 or 7  |
|GAME | GameCredits | G  |
|GAP | Gapcoin | G  |
|GCR | Global Currency Reserve | G  |
|GRC | GridcoinResearch | R or S  |
|GRLC | Garlicoin | G  |
|GRN | GreenCoin | G  |
|GRS | Groestlcoin | F  |
|GRV | Gravium | G  |
|GUN | Guncoin | G or H  |
|HAM | HamRadiocoin | 1  |
|HBN | HoboNickels(and BottleCaps) | E or F  |
|HODL | HOdlcoin | H  |
|IC | Ignition Coin | i  |
|IXC | Ixcoin | x  |
|JBS | Jumbucks | J  |
|JIN | Jincoin | J  |
|KMD | Komodo (and assetchains) | R  |
|KORE | Kore | K  |
|LBRY | LBRY | b  |
|LEAF | Leafcoin | f  |
|LMC | LomoCoin | L  |
|LTC | Litecoin | L  |
|MGD | MassGrid | M  |
|MMC | Memorycoin | M  |
|MNP | MNPCoin | M  |
|MOG | Mogwai | M  |
|MONA | Monacoin | M  |
|MUE | Monetary Unit | 7  |
|MYRIAD | Myriadcoin | M  |
|MZC | Mazacoin | M  |
|NEET | NEETCOIN | N  |
|NEOS | Neoscoin | S  |
|NLG | Gulden | G  |
|NMC | Namecoin | M or N  |
|NVC | Novacoin | 4  |
|NYAN | Nyancoin | K  |
|OK | OK Cash | P  |
|OMC | Omnicoin | o  |
|PIGGY | Piggycoin | p  |
|PINK | Pinkcoin | 2  |
|PIVX | PIVX | D  |
|PKB | Parkbyte | P  |
|PND | Pandacoin | P  |
|POT | Potcoin | P  |
|PPC | Peercoin | P  |
|PTC | Pesetacoin | K  |
|PTS | Protoshares | P  |
|QTUM | QTUM | Q  |
|RBY | Rubycoin | R  |
|RDD | Reddcoin | R  |
|RIC | Riecoin | R  |
|ROI | ROIcoin | R  |
|RVN | Ravencoin | R |
|SCA | Scamcoin | S  |
|SDC | Shadowcoin | S  |
|SKC | Skeincoin | S  |
|SPR | Spreadcoin | S  |
|START | Startcoin | s  |
|SXC | Sexcoin | R or S  |
|TPC | Templecoin | T  |
|TUX | Tuxcoin | T  |
|UIS | Unitus | U  |
|UNO | Unobtanium | u  |
|VIA | Viacoin | V  |
|VIPS | VIPSTARCOIN | V  |
|VPN | Vpncoin | V  |
|VTC | Vertcoin | V  |
|WDC | Worldcoin Global | W  |
|WKC | Wankcoin | 1  |
|WUBS | Dubstepcoin | D  |
|XC | XCurrency | X  |
|XPM | Primecoin | A  |
|YAC | Yacoin | Y  |
|YTN | Yenten | Y  |
|ZNY | BitZeny | Z  |
|ZOOM | Zoom coin | i  |
|ZRC | Ziftrcoin | Z  |

**If you found this repo useful, please consider a donation.  Thank You!**  

 * Donate Bitcoin: 1egacySQXJA8bLHnFhdQQjZBLW1gxSAjc  
