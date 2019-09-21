/*
 * Vanitygen, vanity bitcoin address generator
 * Copyright (C) 2011 <samr7@cs.washington.edu>
 *
 * Vanitygen is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * Vanitygen is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Vanitygen.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <assert.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "oclengine.h"
#include "pattern.h"
#include "util.h"

#include "ticker.h"
char ticker[10];

int GRSFlag = 0;

const char *version = VANITYGEN_VERSION;
const int debug = 0;


void
usage(const char *name)
{
	fprintf(stderr,
"oclVanitygen %s (" OPENSSL_VERSION_TEXT ")\n"
"Usage: %s [-vqrik1NTS] [-d <device>] [-f <filename>|-] [<pattern>...]\n"
"Generates a bitcoin receiving address matching <pattern>, and outputs the\n"
"address and associated private key.  The private key may be stored in a safe\n"
"location or imported into a bitcoin client to spend any balance received on\n"
"the address.\n"
"By default, <pattern> is interpreted as an exact prefix.\n"
"By default, if no device is specified, and the system has exactly one OpenCL\n"
"device, it will be selected automatically, otherwise if the system has\n"
"multiple OpenCL devices and no device is specified, an error will be\n"
"reported.  To use multiple devices simultaneously, specify the -D option for\n"
"each device.\n"
"\n"
"Options:\n"
"-v            Verbose output\n"
"-q            Quiet output\n"
"-r            Use regular expression match instead of prefix\n"
"              (Feasibility of expression is not checked)\n"
"-i            Case-insensitive prefix search\n"
"-k            Keep pattern and continue search after finding a match\n"
"-1            Stop after first match\n"
"-a <amount>   Stop after generating <amount> addresses/keys\n"
"-C <altcoin>  Generate an address for specific altcoin, use \"-C LIST\" to view\n"
"              a list of all available altcoins, argument is case sensitive!\n"
"-X <version>  Generate address with the given version\n"
"-Y <version>  Specify private key version (-X provides public key)\n"
"-F <format>   Generate address with the given format (pubkey, compressed)\n"
"-P <pubkey>   Use split-key method with <pubkey> as base public key\n"
"-e            Encrypt private keys, prompt for password\n"
"-E <password> Encrypt private keys with <password> (UNSAFE)\n"
"-p <platform> Select OpenCL platform\n"
"-d <device>   Select OpenCL device\n"
"-D <devstr>   Use OpenCL device, identified by device string\n"
"              Form: <platform>:<devicenumber>[,<options>]\n"
"              Example: 0:0,grid=1024x1024\n"
"-S            Safe mode, disable OpenCL loop unrolling optimizations\n"
"-w <worksize> Set work items per thread in a work unit\n"
"-t <threads>  Set target thread count per multiprocessor\n"
"-g <x>x<y>    Set grid size\n"
"-b <invsize>  Set modular inverse ops per thread\n"
"-V            Enable kernel/OpenCL/hardware verification (SLOW)\n"
"-f <file>     File containing list of patterns, one per line\n"
"              (Use \"-\" as the file name for stdin)\n"
"-o <file>     Write pattern matches to <file>\n"
"-s <file>     Seed random number generator from <file>\n"
"-Z <prefix>   Private key prefix in hex (1Address.io Dapp front-running protection)\n"
"-z            Format output of matches in CSV(disables verbose mode)\n"
"              Output as [COIN],[PREFIX],[ADDRESS],[PRIVKEY]\n",
version, name);
}

#define MAX_DEVS 32
#define MAX_FILE 4

int
main(int argc, char **argv)
{
	int addrtype = 0;
	int privtype = 128;
	int regex = 0;
	int caseinsensitive = 0;
	int opt;
	char pwbuf[128];
	int platformidx = -1, deviceidx = -1;
	int prompt_password = 0;
	char *seedfile = NULL;
	char **patterns, *pend;
	int verbose = 1;
	int npatterns = 0;
	int nthreads = 0;
	int worksize = 0;
	int nrows = 0, ncols = 0;
	int invsize = 0;
	int remove_on_match = 1;
	int only_one = 0;
	int numpairs = 0;
	int csv = 0;
	int verify_mode = 0;
	int safe_mode = 0;
	vg_context_t *vcp = NULL;
	vg_ocl_context_t *vocp = NULL;
	EC_POINT *pubkey_base = NULL;
	const char *result_file = NULL;
	const char *key_password = NULL;
	char *devstrs[MAX_DEVS];
	int ndevstrs = 0;
	int opened = 0;
	char privkey_prefix[32];
	int privkey_prefix_length = 0;

	FILE *pattfp[MAX_FILE], *fp;
	int pattfpi[MAX_FILE];
	int npattfp = 0;
	int pattstdin = 0;
	int compressed = 0;

	int i;

	while ((opt = getopt(argc, argv,
			     "vqrik1zC:X:Y:F:eE:p:P:d:w:t:g:b:VSh?f:o:s:D:Z:a:")) != -1) {
		switch (opt) {
		case 'r':
			regex = 1;
			break;
		case 'v':
			verbose = 2;
			break;
		case 'q':
			verbose = 0;
			break;
		case 'i':
			caseinsensitive = 1;
			break;
		case 'k':
			remove_on_match = 0;
			break;
		case '1':
			only_one = 1;
			break;
		case 'a':
			remove_on_match = 0;
			numpairs = atoi(optarg);
			break;
		case 'z':
		      csv = 1;
		      break;

/*BEGIN ALTCOIN GENERATOR*/

		case 'C':
			strcpy(ticker, optarg);
			strcat(ticker, " ");
			/* Start AltCoin Generator */
			if (strcmp(optarg, "LIST")== 0) {
				fprintf(stderr,
					"Usage example \"./oclvanitygen -C LTC Lfoo\"\n"
					"List of Available Alt-Coins for Address Generation\n"
					"---------------------------------------------------\n"
					"Argument(UPPERCASE) : Coin : Address Prefix\n"
					"---------------\n"
					"42 : 42coin : 4\n"
					"AC : Asiacoin : A\n"
					"ACM : Actinium : N\n"
					"AIB : Advanced Internet Block by IOBOND : A\n"
					"ANC : Anoncoin : A\n"
					"ARS : Arkstone : A\n"
					"ATMOS : Atmos : N\n"
					"AUR : Auroracoin : A\n"
					"AQX : Aquila : A\n"
					"AXE : Axe : P\n"
					"BLAST : BLAST : B\n"
					"BLK : Blackcoin : B\n"
					"BWK : Bulwark : b\n"
					"BQC : BBQcoin : b\n"
					"BTC : Bitcoin : 1\n"
					"TEST : Bitcoin Testnet : m or n\n"
					"BTCD : Bitcoin Dark : R\n"
					"CARE : Carebit : C\n"
					"CCBC : CryptoCashBackCoin : C\n"
					"CCC : Chococoin : 7\n"
					"CCN : Cannacoin : C\n"
					"CDN : Canadaecoin : C\n"
					"CIV : Civitas : C\n"
					"tCIV : Civitas Testnet : y\n"
					"CLAM : Clamcoin : x\n"
					"CNC : Chinacoin : C\n"
					"CNOTE : C-Note : C\n"
					"CON : PayCon : P\n"
					"CRW : Crown : 1\n"
					"CPU : CPUchain : C\n"
					"DASH : Dash : X\n"
					"DEEPONION : DeepOnion : D\n"
					"DNR: Denarius: D\n"
					"DGB : Digibyte : D\n"
					"DGC : Digitalcoin : D\n"
					"DMD : Diamond : d\n"
					"DOGED : Doge Dark Coin : D\n"
					"DOGE : Dogecoin : D\n"
					"DOPE : Dopecoin : 4\n"
					"DVC : Devcoin : 1\n"
					"EFL : Electronic-Gulden-Foundation : L\n"
					"EMC : Emercoin : E\n"
					"FAIR : Faircoin2 : f\n"
					"FLOZ : FLOZ : F\n"
					"FTC : Feathercoin : 6 or 7\n"
					"GAME : GameCredits : G\n"
					"GAP : Gapcoin : G\n"
					"GCR : Global Currency Reserve : G\n"
					"GRC : GridcoinResearch : R or S\n"
					"GRLC : Garlicoin : G\n"
					"GRN : GreenCoin : G\n"
					"GRS : Groestlcoin : F\n"
					"GRV : Gravium : G\n"
					"GUN : Guncoin : G or H\n"
					"HAM : HamRadiocoin : 1\n"
					"HBN : HoboNickels(BottleCaps) : E or F\n"
					"HODL : HOdlcoin : H\n"
					"IC : Ignition Coin : i\n"
					"IXC : Ixcoin : x\n"
					"IPS : Ipsum : i\n"
					"JBS : Jumbucks : J\n"
					"JIN : Jincoin : J\n"
					"KMD : Komodo (and assetchains) : R\n"
					"KORE : Kore : K\n"
					"LBRY : LBRY : b\n"
					"LEAF : Leafcoin : f\n"
					"LMC : LomoCoin : L\n"
					"LTC : Litecoin : L\n"
					"MGD : MassGrid : M\n"
					"MMC : Memorycoin : M\n"
					"MNC : Mincoin : M\n"
					"tMNC : Mincoin Testnet : m or n\n"
					"MNP : MNPCoin : M\n"
					"MOG : Mogwai : M\n"
					"MONA : Monacoin : M\n"
					"MUE : Monetary Unit : 7\n"
					"MYRIAD : Myriadcoin : M\n"
					"MZC : Mazacoin : M\n"
					"NEET : NEETCOIN : N\n"
					"NEOS : Neoscoin : S\n"
					"NLG : Gulden : G\n"
					"NMC : Namecoin : M or N\n"
					"NVC : Novacoin : 4\n"
					"NYAN : Nyancoin : K\n"
					"OK : OK Cash : P\n"
					"OMC : Omnicoin : o\n"
					"PIGGY : Piggycoin : p\n"
					"PINK : Pinkcoin : 2\n"
					"PIVX : PIVX : D\n"
					"PKB : Parkbyte : P\n"
					"PND : Pandacoin : P\n"
					"POT : Potcoin : P\n"
					"PPC : Peercoin : P\n"
					"PTC : Pesetacoin : K\n"
					"PTS : Protoshares : P\n"
					"QTUM : Qtum : Q\n"
					"RBY : Rubycoin : R\n"
					"RDD : Reddcoin : R\n"
					"RIC : Riecoin : R\n"
					"ROI : ROIcoin : R\n"
					"RVN : Ravencoin : R\n"
					"SCA : Scamcoin : S\n"
					"SDC : Shadowcoin : S\n"
					"SKC : Skeincoin : S\n"
					"SPR : Spreadcoin : S\n"
					"START : Startcoin : s\n"
					"SXC : Sexcoin : R or S\n"
					"TPC : Templecoin : T\n"
					"TUX : Tuxcoin : T\n"
					"UIS : Unitus : U\n"
					"UNO : Unobtanium : u\n"
					"VIA : Viacoin : V\n"
					"VIPS : VIPSTARCOIN : V\n"
					"VPN : Vpncoin : V\n"
					"VTC : Vertcoin : V\n"
					"WDC : Worldcoin Global : W\n"
					"WKC : Wankcoin : 1\n"
					"WUBS : Dubstepcoin : D\n"
					"XC : XCurrency : X\n"
					"XPM : Primecoin : A\n"
					"YAC : Yacoin : Y\n"
					"YTN : Yenten : Y\n"
					"ZNY : BitZeny : Z\n"
					"ZOOM : Zoom coin : i\n"
					"ZRC : Ziftrcoin : Z\n"
					);
					return 1;
			}
			else
			if (strcmp(optarg, "ACM")== 0) {
				fprintf(stderr,
					"Generating Actinium Address\n");
					addrtype = 53;
					privtype = 181;
					break;
			}
			else
			if (strcmp(optarg, "AQX")== 0) {
				fprintf(stderr,
					"Generating Aquila Address\n");
					addrtype = 75;
					privtype = 212;
					break;
			}
			else
			if (strcmp(optarg, "IPS")== 0) {
				fprintf(stderr,
					"Generating Ipsum Address\n");
					addrtype = 103;
					privtype = 138;
					break;
			}
			else
			if (strcmp(optarg, "CCBC")== 0) {
				fprintf(stderr,
					"Generating CryptoCashBackCoin Address\n");
					addrtype = 63;
					privtype = 212;
					break;
			}
			else
			if (strcmp(optarg, "PIVX")== 0) {
				fprintf(stderr,
					"Generating PIVX Address\n");
					addrtype = 30;
					privtype = 212;
					break;
			}
			else
			if (strcmp(optarg, "KMD")== 0) {
				fprintf(stderr,
					"Generating KMD Address\n");
					addrtype = 60;
					privtype = 188;
					break;
			}
			else
			if (strcmp(optarg, "PINK")== 0) {
				fprintf(stderr,
					"Generating PINK Address\n");
					addrtype = 3;
					privtype = 131;
					break;
			}
			else
			if (strcmp(optarg, "DEEPONION")== 0) {
				fprintf(stderr,
					"Generating DEEPONION Address\n");
					addrtype = 31;
					privtype = 159;
					break;
			}
			else
			if (strcmp(optarg, "DNR")== 0) {
				fprintf(stderr,
					"Generating DNR Address\n");
					addrtype = 30;
					privtype = 158;
					break;
			}
			else
			if (strcmp(optarg, "DMD")== 0) {
				fprintf(stderr,
					"Generating DMD Address\n");
					addrtype = 90;
					privtype = 218;
					break;
			}
			else
			if (strcmp(optarg, "GRS")== 0) {
				fprintf(stderr,
					"Generating GRS Address\n");
					GRSFlag = 1;
					addrtype = 36;
					privtype = 128;
					break;
			}
			else
			if (strcmp(optarg, "GUN")== 0) {
				fprintf(stderr,
					"Generating GUN Address\n");
					addrtype = 39;
					privtype = 167;
					break;
			}
			else
			if (strcmp(optarg, "HAM")== 0) {
				fprintf(stderr,
					"Generating HAM Address\n");
					addrtype = 0;
					privtype = 128;
					break;
			}
			else
			if (strcmp(optarg, "DVC")== 0) {
				fprintf(stderr,
					"Generating DVC Address\n");
					addrtype = 0;
					privtype = 128;
					break;
			}
			else
			if (strcmp(optarg, "42")== 0) {
				fprintf(stderr,
					"Generating 42 Address\n");
					addrtype = 8;
					privtype = 136;
					break;
			}
			else
			if (strcmp(optarg, "WKC")== 0) {
				fprintf(stderr,
					"Generating WKC Address\n");
					addrtype = 0;
					privtype = 128;
					break;
			}
			else
			if (strcmp(optarg, "SPR")== 0) {
				fprintf(stderr,
					"Generating SPR Address\n");
					addrtype = 63;
					privtype = 191;
					break;
			}
			else
			if (strcmp(optarg, "SCA")== 0) {
				fprintf(stderr,
					"Generating SCA Address\n");
					addrtype = 63;
					privtype = 191;
					break;
			}
			else
			if (strcmp(optarg, "GAP")== 0) {
				fprintf(stderr,
					"Generating GAP Address\n");
					addrtype = 38;
					privtype = 166;
					break;
			}
			else
			if (strcmp(optarg, "CCC")== 0) {
				fprintf(stderr,
					"Generating CCC Address\n");
					addrtype = 15;
					privtype = 224;
					break;
			}
			else
			if (strcmp(optarg, "PIGGY")== 0) {
				fprintf(stderr,
					"Generating PIGGY Address\n");
					addrtype = 118;
					privtype = 246;
					break;
			}
			else
			if (strcmp(optarg, "WDC")== 0) {
				fprintf(stderr,
					"Generating WDC Address\n");
					addrtype = 73;
					privtype = 201;
					break;
			}
			else
			if (strcmp(optarg, "XC")== 0) {
				fprintf(stderr,
					"Generating XC Address\n");
					addrtype = 75;
					privtype = 203;
					break;
			}
			else
			if (strcmp(optarg, "WUBS")== 0) {
				fprintf(stderr,
					"Generating WUBS Address\n");
					addrtype = 29;
					privtype = 157;
					break;
			}
			else
			if (strcmp(optarg, "SXC")== 0) {
				fprintf(stderr,
					"Generating SXC Address\n");
					addrtype = 62;
					privtype = 190;
					break;
			}
			else
			if (strcmp(optarg, "SKC")== 0) {
				fprintf(stderr,
					"Generating SKC Address\n");
					addrtype = 63;
					privtype = 226;
					break;
			}
			else
			if (strcmp(optarg, "PTS")== 0) {
				fprintf(stderr,
					"Generating PTS Address\n");
					addrtype = 56;
					privtype = 184;
					break;
			}
			else
			if (strcmp(optarg, "NLG")== 0) {
				fprintf(stderr,
					"Generating NLG Address\n");
					addrtype = 38;
					privtype = 166;
					break;
			}
			else
			if (strcmp(optarg, "MMC")== 0) {
				fprintf(stderr,
					"Generating MMC Address\n");
					addrtype = 50;
					privtype = 178;
					break;
			}
			else
			if (strcmp(optarg, "LEAF")== 0) {
				fprintf(stderr,
					"Generating LEAF Address\n");
					addrtype = 95;
					privtype = 223;
					break;
			}
			else
			if (strcmp(optarg, "ROI")== 0) {
				fprintf(stderr,
					"Generating ROI Address\n");
					addrtype = 60;
					privtype = 128;
					break;
			}
			else
			if (strcmp(optarg, "HODL")== 0) {
				fprintf(stderr,
					"Generating HODL Address\n");
					addrtype = 40;
					privtype = 168;
					break;
			}
			else
			if (strcmp(optarg, "FLOZ")== 0) {
				fprintf(stderr,
					"Generating FLOZ Address\n");
					addrtype = 35;
					privtype = 163;
					break;
			}
			else
			if (strcmp(optarg, "FAIR")== 0) {
				fprintf(stderr,
					"Generating FAIR Address\n");
					addrtype = 95;
					privtype = 223;
					break;
			}
			else
			if (strcmp(optarg, "CON")== 0) {
				fprintf(stderr,
					"Generating CON Address\n");
					addrtype = 55;
					privtype = 183;
					break;
			}
			else
			if (strcmp(optarg, "AUR")== 0) {
				fprintf(stderr,
					"Generating AUR Address\n");
					addrtype = 23;
					privtype = 151;
					break;
			}
			else
			if (strcmp(optarg, "GRC")== 0) {
				fprintf(stderr,
					"Generating GRC Address\n");
					addrtype = 62;
					privtype = 190;
					break;
			}
			else
			if (strcmp(optarg, "RIC")== 0) {
				fprintf(stderr,
					"Generating RIC Address\n");
					addrtype = 60;
					privtype = 128;
					break;
			}
			else
			if (strcmp(optarg, "UNO")== 0) {
				fprintf(stderr,
					"Generating UNO Address\n");
					addrtype = 130;
					privtype = 224;
					break;
			}
			else
			if (strcmp(optarg, "UIS")== 0) {
				fprintf(stderr,
					"Generating UIS Address\n");
					addrtype = 68;
					privtype = 132;
					break;
			}
			else
			if (strcmp(optarg, "MYRIAD")== 0) {
				fprintf(stderr,
					"Generating MYRIAD Address\n");
					addrtype = 50;
					privtype = 178;
					break;
			}
			else
			if (strcmp(optarg, "BQC")== 0) {
				fprintf(stderr,
					"Generating BQC Address\n");
					addrtype = 85;
					privtype = 213;
					break;
			}
			else
			if (strcmp(optarg, "YAC")== 0) {
				fprintf(stderr,
					"Generating YAC Address\n");
					addrtype = 77;
					privtype = 205;
					break;
			}
			else
			if (strcmp(optarg, "PTC")== 0) {
				fprintf(stderr,
					"Generating PTC Address\n");
					addrtype = 47;
					privtype = 175;
					break;
			}
			else
			if (strcmp(optarg, "RDD")== 0) {
				fprintf(stderr,
					"Generating RDD Address\n");
					addrtype = 61;
					privtype = 189;
					break;
			}
			else
			if (strcmp(optarg, "NYAN")== 0) {
				fprintf(stderr,
					"Generating NYAN Address\n");
					addrtype = 45;
					privtype = 173;
					break;
			}
			else
			if (strcmp(optarg, "IXC")== 0) {
				fprintf(stderr,
					"Generating IXC Address\n");
					addrtype = 138;
					privtype = 266;
					break;
			}
			else
			if (strcmp(optarg, "CNC")== 0) {
				fprintf(stderr,
					"Generating CNC Address\n");
					addrtype = 28;
					privtype = 156;
					break;
			}
			else
			if (strcmp(optarg, "CNOTE")== 0) {
				fprintf(stderr,
					"Generating C-Note Address\n");
					addrtype = 28;
					privtype = 186;
					break;
			}
			else
			if (strcmp(optarg, "ARS")== 0) {
				fprintf(stderr,
					"Generating ARS Address\n");
					addrtype = 23;
					privtype = 151;
					break;
			}
			else
			if (strcmp(optarg, "ANC")== 0) {
				fprintf(stderr,
					"Generating ANC Address\n");
					addrtype = 23;
					privtype = 151;
					break;
			}
			else
			if (strcmp(optarg, "OMC")== 0) {
				fprintf(stderr,
					"Generating OMC Address\n");
					addrtype = 115;
					privtype = 243;
					break;
			}
			else
			if (strcmp(optarg, "POT")== 0) {
				fprintf(stderr,
					"Generating POT Address\n");
					addrtype = 55;
					privtype = 183;
					break;
			}
			else
			if (strcmp(optarg, "EFL")== 0) {
				fprintf(stderr,
					"Generating EFL Address\n");
					addrtype = 48;
					privtype = 176;
					break;
			}
			else
			if (strcmp(optarg, "EMC")== 0) {
				fprintf(stderr,
						"Generating Emercoin Address\n");
				addrtype = 33;
				privtype = 128;
				break;
			}
			else
			if (strcmp(optarg, "DOGED")== 0) {
				fprintf(stderr,
					"Generating DOGED Address\n");
					addrtype = 30;
					privtype = 158;
					break;
			}
			else
			if (strcmp(optarg, "OK")== 0) {
				fprintf(stderr,
					"Generating OK Address\n");
					addrtype = 55;
					privtype = 183;
					break;
			}
			else
			if (strcmp(optarg, "AIB")== 0) {
				fprintf(stderr,
					"Generating AIB Address\n");
					addrtype = 23;
					privtype = 151;
					break;
			}
			else
			if (strcmp(optarg, "TPC")== 0) {
				fprintf(stderr,
					"Generating TPC Address\n");
					addrtype = 65;
					privtype = 193;
					break;
			}
			else
			if (strcmp(optarg, "DOPE")== 0) {
				fprintf(stderr,
					"Generating DOPE Address\n");
					addrtype = 8;
					privtype = 136;
					break;
			}
			else
			if (strcmp(optarg, "BTCD")== 0) {
				fprintf(stderr,
					"Generating BTCD Address\n");
					addrtype = 60;
					privtype = 188;
					break;
			}
			else
			if (strcmp(optarg, "IC")== 0) {
				fprintf(stderr,
					"Generating IC Address\n");
					addrtype = 103;
					privtype = 138;
					break;
			}
			else
			if (strcmp(optarg, "AC")== 0) {
				fprintf(stderr,
					"Generating AC Address\n");
					addrtype = 23;
					privtype = 151;
					break;
			}
			else
			if (strcmp(optarg, "NVC")== 0) {
				fprintf(stderr,
					"Generating NVC Address\n");
					addrtype = 8;
					privtype = 136;
					break;
			}
			else
			if (strcmp(optarg, "HBN")== 0) {
				fprintf(stderr,
					"Generating HBN Address\n");
					addrtype = 34;
					privtype = 162;
					break;
			}
			else
			if (strcmp(optarg, "GCR")== 0) {
				fprintf(stderr,
					"Generating GCR Address\n");
					addrtype = 38;
					privtype = 154;
					break;
			}
			else
			if (strcmp(optarg, "START")== 0) {
				fprintf(stderr,
					"Generating START Address\n");
					addrtype = 125;
					privtype = 253;
					break;
			}
			else
			if (strcmp(optarg, "PND")== 0) {
				fprintf(stderr,
					"Generating PND Address\n");
					addrtype = 55;
					privtype = 183;
					break;
			}
			else
			if (strcmp(optarg, "PKB")== 0) {
				fprintf(stderr,
					"Generating PKB Address\n");
					addrtype = 55;
					privtype = 183;
					break;
			}
			else
			if (strcmp(optarg, "SDC")== 0) {
				fprintf(stderr,
					"Generating SDC Address\n");
					addrtype = 63;
					privtype = 191;
					break;
			}
			else
			if (strcmp(optarg, "CDN")== 0) {
				fprintf(stderr,
					"Generating CDN Address\n");
					addrtype = 28;
					privtype = 156;
					break;
			}
			else
			if (strcmp(optarg, "VPN")== 0) {
				fprintf(stderr,
					"Generating VPN Address\n");
					addrtype = 71;
					privtype = 199;
					break;
			}
			else
			if (strcmp(optarg, "ZOOM")== 0) {
				fprintf(stderr,
					"Generating ZOOM Address\n");
					addrtype = 103;
					privtype = 231;
					break;
			}
			else
			if (strcmp(optarg, "MUE")== 0) {
				fprintf(stderr,
					"Generating MUE Address\n");
					addrtype = 15;
					privtype = 143;
					break;
			}
			else
			if (strcmp(optarg, "VTC")== 0) {
				fprintf(stderr,
					"Generating VTC Address\n");
					addrtype = 71;
					privtype = 199;
					break;
			}
			else
			if (strcmp(optarg, "ZRC")== 0) {
				fprintf(stderr,
					"Generating ZRC Address\n");
					addrtype = 80;
					privtype = 208;
					break;
			}
			else
			if (strcmp(optarg, "JBS")== 0) {
				fprintf(stderr,
					"Generating JBS Address\n");
					addrtype = 43;
					privtype = 171;
					break;
			}
			else
			if (strcmp(optarg, "JIN")== 0) {
				fprintf(stderr,
					"Generating JIN Address\n");
					addrtype = 43;
					privtype = 171;
					break;
			}
			else
			if (strcmp(optarg, "NEOS")== 0) {
				fprintf(stderr,
					"Generating NEOS Address\n");
					addrtype = 63;
					privtype = 239;
					break;
			}
			else
			if (strcmp(optarg, "XPM")== 0) {
				fprintf(stderr,
					"Generating XPM Address\n");
					addrtype = 23;
					privtype = 151;
					break;
			}
			else
			if (strcmp(optarg, "CLAM")== 0) {
				fprintf(stderr,
					"Generating CLAM Address\n");
					addrtype = 137;
					privtype = 133;
					break;
			}
			else
			if (strcmp(optarg, "MONA")== 0) {
				fprintf(stderr,
					"Generating MONA Address\n");
					addrtype = 50;
					privtype = 176;
					break;
			}
			else
			if (strcmp(optarg, "DGB")== 0) {
				fprintf(stderr,
					"Generating DGB Address\n");
					addrtype = 30;
					privtype = 128;
					break;
			}
			else
			if (strcmp(optarg, "CCN")== 0) {
				fprintf(stderr,
					"Generating CCN Address\n");
					addrtype = 28;
					privtype = 156;
					break;
			}
			else
			if (strcmp(optarg, "DGC")== 0) {
				fprintf(stderr,
					"Generating DGC Address\n");
					addrtype = 30;
					privtype = 158;
					break;
			}
			else
			if (strcmp(optarg, "RBY")== 0) {
				fprintf(stderr,
					"Generating RBY Address\n");
					addrtype = 61;
					privtype = 189;
					break;
			}
			else
			if (strcmp(optarg, "VIA")== 0) {
				fprintf(stderr,
					"Generating VIA Address\n");
					addrtype = 71;
					privtype = 199;
					break;
			}
			else
			if (strcmp(optarg, "MZC")== 0) {
				fprintf(stderr,
					"Generating MZC Address\n");
					addrtype = 50;
					privtype = 224;
					break;
			}
			else
			if (strcmp(optarg, "BLAST")== 0) {
				fprintf(stderr,
					"Generating BLAST Address\n");
					addrtype = 25;
					privtype = 239;
					break;
			}
			else
			if (strcmp(optarg, "BLK")== 0) {
				fprintf(stderr,
					"Generating BLK Address\n");
					addrtype = 25;
					privtype = 153;
					break;
			}
			else
			if (strcmp(optarg, "FTC")== 0) {
				fprintf(stderr,
					"Generating FTC Address\n");
					addrtype = 14;
					privtype = 142;
					break;
			}
			else
			if (strcmp(optarg, "PPC")== 0) {
				fprintf(stderr,
					"Generating PPC Address\n");
					addrtype = 55;
					privtype = 183;
					break;
			}
			else
			if (strcmp(optarg, "DASH")== 0) {
				fprintf(stderr,
					"Generating DASH Address\n");
					addrtype = 76;
					privtype = 204;
					break;
			}
			else
			if (strcmp(optarg, "MGD")== 0) {
				fprintf(stderr,
					"Generating MassGrid Address\n");
					addrtype = 50;
					privtype = 25;
					break;
			}
			else
			if (strcmp(optarg, "MOG")== 0) {
				fprintf(stderr,
					"Generating Mogwai Address\n");
					addrtype = 50;
					privtype = 204;
					break;
			}
			else
			if (strcmp(optarg, "BTC")== 0) {
				fprintf(stderr,
					"Generating BTC Address\n");
					addrtype = 0;
					privtype = 128;
					break;
			}
			else
			if (strcmp(optarg, "TEST")== 0) {
				fprintf(stderr,
					"Generating BTC Testnet Address\n");
					addrtype = 111;
					privtype = 239;
					break;
			}
			else
			if (strcmp(optarg, "DOGE")== 0) {
				fprintf(stderr,
					"Generating DOGE Address\n");
					addrtype = 30;
					privtype = 158;
					break;
			}
			else
			if (strcmp(optarg, "LBRY")== 0) {
				fprintf(stderr,
					"Generating LBRY Address\n");
					addrtype = 85;
					privtype = 28;
					break;
			}
			else
			if (strcmp(optarg, "LMC")== 0) {
				fprintf(stderr,
					"Generating LomoCoin Address\n");
					addrtype = 48;
					privtype = 176;
					break;
			}
			else
			if (strcmp(optarg, "LTC")== 0) {
				fprintf(stderr,
					"Generating LTC Address\n");
					addrtype = 48;
					privtype = 176;
					break;
			}
			else
			if (strcmp(optarg, "GRLC")== 0) {
				fprintf(stderr,
					"Generating GRLC Address\n");
					addrtype = 38;
					privtype = 176;
					break;
			}
			else
			if (strcmp(optarg, "GRN")== 0) {
				fprintf(stderr,
					"Generating GRN Address\n");
					addrtype = 38;
					privtype = 166;
					break;
			}
			else
			if (strcmp(optarg, "BWK")== 0) {
				fprintf(stderr,
					"Generating BWK Address\n");
					addrtype = 85;
					privtype = 212;
					break;
			}
			else
			if (strcmp(optarg, "NMC")== 0) {
				fprintf(stderr,
					"Generating NMC Address\n");
					addrtype = 52;
					privtype = 180;
					break;
			}
			else
			if (strcmp(optarg, "GAME")== 0) {
				fprintf(stderr,
					"Generating GAME Address\n");
					addrtype = 38;
					privtype = 166;
					break;
			}
			else
			if (strcmp(optarg, "CRW")== 0) {
				fprintf(stderr,
					"Generating CRW Address\n");
					addrtype = 0;
					privtype = 128;
					break;
			}
			else
			if (strcmp(optarg, "QTUM")== 0) {
				fprintf(stderr,
					"Generating QTUM Address\n");
					addrtype = 58;
					privtype = 128;
					break;
			}
			else
			if (strcmp(optarg, "ATMOS")== 0) {
				fprintf(stderr,
					"Generating ATMOS Address\n");
					addrtype = 53;
					privtype = 153;
					break;
			}
			else
			if (strcmp(optarg, "AXE")== 0) {
				fprintf(stderr,
					"Decrypting AXE Address\n");
					addrtype = 55;
					privtype = 204;
					break;
			}
			else
			if (strcmp(optarg, "ZNY")== 0) {
				fprintf(stderr,
					"Generating BitZeny Address\n");
					addrtype = 81;
					privtype = 128;
					break;
			}
			else
			if (strcmp(optarg, "NEET")== 0) {
				fprintf(stderr,
					"Generating NEETCOIN Address\n");
					addrtype = 53;
					privtype = 181;
					break;
			}
			else
			if (strcmp(optarg, "YTN")== 0) {
				fprintf(stderr,
					"Generating Yenten Address\n");
					addrtype = 78;
					privtype = 123;
					break;
			}
			else
			if (strcmp(optarg, "RVN")== 0) {
				fprintf(stderr,
					"Generating Ravencoin Address\n");
					addrtype = 60;
					privtype = 128;
					break;
			}
			else
			if (strcmp(optarg, "VIPS")== 0) {
				fprintf(stderr,
					"Generating VIPSTARCOIN Address\n");
					addrtype = 70;
					privtype = 128;
					break;
			}
			else
			if (strcmp(optarg, "CIV")== 0) {
				fprintf(stderr,
					"Generating Civitas Address\n");
					addrtype = 28;
					privtype = 212;
					break;
			}
			else
			if (strcmp(optarg, "tCIV")== 0) {
				fprintf(stderr,
					"Generating Civitas Testnet Address\n");
					addrtype = 139;
					privtype = 239;
					break;
			}
			else
			if (strcmp(optarg, "GRV")== 0) {
				fprintf(stderr,
					"Generating Gravium Address\n");
					addrtype = 38;
					privtype = 166;
					break;
			}
			else
			if (strcmp(optarg, "MNP")== 0) {
				fprintf(stderr,
					"Generating MNPCoin Address\n");
					addrtype = 50;
					privtype = 55;
					break;
			}
			else
			if (strcmp(optarg, "CARE")== 0) {
				fprintf(stderr,
					"Generating Carebit Address\n");
					addrtype = 28;
					privtype = 55;
					break;
			}
			else
			if (strcmp(optarg, "TUX")== 0) {
				fprintf(stderr,
					"Generating TUX Address\n");
					addrtype = 65;
					privtype = 193;
					break;
                        }
                        else
			if (strcmp(optarg, "KORE")== 0) {
				fprintf(stderr,
					"Generating Kore Address\n");
					addrtype = 45;
					privtype = 128;
					break;
			}
			else
			if (strcmp(optarg, "MNC")== 0) {
				fprintf(stderr,
					"Generating MNC Address\n");
					addrtype = 50;
					privtype = 178;
					break;
			}
			else
			if (strcmp(optarg, "tMNC")== 0) {
				fprintf(stderr,
					"Generating MNC Testnet Address\n");
					addrtype = 111;
					privtype = 239;
					break;
			}
			else
			if (strcmp(optarg, "CPU")== 0) {
				fprintf(stderr,
					"Decrypting CPUchain Address\n");
					addrtype = 28;
					privtype = 128;
					break;
			}
			break;

/*END ALTCOIN GENERATOR*/

		case 'X':
			addrtype = atoi(optarg);
			privtype = 128 + addrtype;
			break;
		case 'Y':
			/* Overrides privtype of 'X' but leaves all else intact */
			privtype = atoi(optarg);
			break;
		case 'F':
			if (!strcmp(optarg, "compressed"))
				compressed = 1;
			else
			if (strcmp(optarg, "pubkey")) {
				fprintf(stderr,
					"Invalid format '%s'\n", optarg);
				return 1;
			}
			break;
		case 'e':
			prompt_password = 1;
			break;
		case 'E':
			key_password = optarg;
			break;
		case 'p':
			platformidx = atoi(optarg);
			break;
		case 'd':
			deviceidx = atoi(optarg);
			break;
		case 'w':
			worksize = atoi(optarg);
			if (worksize == 0) {
				fprintf(stderr,
					"Invalid work size '%s'\n", optarg);
				return 1;
			}
			break;
		case 't':
			nthreads = atoi(optarg);
			if (nthreads == 0) {
				fprintf(stderr,
					"Invalid thread count '%s'\n", optarg);
				return 1;
			}
			break;
		case 'g':
			nrows = 0;
			ncols = strtol(optarg, &pend, 0);
			if (pend && *pend == 'x') {
				nrows = strtol(pend+1, NULL, 0);
			}
			if (!nrows || !ncols) {
				fprintf(stderr,
					"Invalid grid size '%s'\n", optarg);
				return 1;
			}
			break;
		case 'b':
			invsize = atoi(optarg);
			if (!invsize) {
				fprintf(stderr,
					"Invalid modular inverse size '%s'\n",
					optarg);
				return 1;
			}
			if (invsize & (invsize - 1)) {
				fprintf(stderr,
					"Modular inverse size must be "
					"a power of 2\n");
				return 1;
			}
			break;
		case 'V':
			verify_mode = 1;
			break;
		case 'S':
			safe_mode = 1;
			break;
		case 'D':
			if (ndevstrs >= MAX_DEVS) {
				fprintf(stderr,
					"Too many OpenCL devices (limit %d)\n",
					MAX_DEVS);
				return 1;
			}
			devstrs[ndevstrs++] = optarg;
			break;
		case 'P': {
			if (pubkey_base != NULL) {
				fprintf(stderr,
					"Multiple base pubkeys specified\n");
				return 1;
			}
			EC_KEY *pkey = vg_exec_context_new_key();
			pubkey_base = EC_POINT_hex2point(
				EC_KEY_get0_group(pkey),
				optarg, NULL, NULL);
			EC_KEY_free(pkey);
			if (pubkey_base == NULL) {
				fprintf(stderr,
					"Invalid base pubkey\n");
				return 1;
			}
			break;
		}
		case 'f':
			if (npattfp >= MAX_FILE) {
				fprintf(stderr,
					"Too many input files specified\n");
				return 1;
			}
			if (!strcmp(optarg, "-")) {
				if (pattstdin) {
					fprintf(stderr, "ERROR: stdin "
						"specified multiple times\n");
					return 1;
				}
				fp = stdin;
			} else {
				fp = fopen(optarg, "r");
				if (!fp) {
					fprintf(stderr,
						"Could not open %s: %s\n",
						optarg, strerror(errno));
					return 1;
				}
			}
			pattfp[npattfp] = fp;
			pattfpi[npattfp] = caseinsensitive;
			npattfp++;
			break;
		case 'o':
			if (result_file) {
				fprintf(stderr,
					"Multiple output files specified\n");
				return 1;
			}
			result_file = optarg;
			break;
		case 's':
			if (seedfile != NULL) {
				fprintf(stderr,
					"Multiple RNG seeds specified\n");
				return 1;
			}
			seedfile = optarg;
			break;
		case 'Z':
			assert(strlen(optarg) % 2 == 0);
			privkey_prefix_length = strlen(optarg)/2;
			for (size_t i = 0; i < privkey_prefix_length; i++) {
				int value; // Can't sscanf directly to char array because of overlapping on Win32
				sscanf(&optarg[i*2], "%2x", &value);
				privkey_prefix[privkey_prefix_length - 1 - i] = value;
			}
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

#if OPENSSL_VERSION_NUMBER < 0x10000000L
	/* Complain about older versions of OpenSSL */
	if (verbose > 0) {
		fprintf(stderr,
			"WARNING: Built with " OPENSSL_VERSION_TEXT "\n"
			"WARNING: Use OpenSSL 1.0.0d+ for best performance\n");
	}
#endif

	if (caseinsensitive && regex)
		fprintf(stderr,
			"WARNING: case insensitive mode incompatible with "
			"regular expressions\n");

	if (seedfile) {
		opt = -1;
#if !defined(_WIN32)
		{	struct stat st;
			if (!stat(seedfile, &st) &&
			    (st.st_mode & (S_IFBLK|S_IFCHR))) {
				opt = 32;
		} }
#endif
		opt = RAND_load_file(seedfile, opt);
		if (!opt) {
			fprintf(stderr, "Could not load RNG seed %s\n", optarg);
			return 1;
		}
		if (verbose > 0) {
			fprintf(stderr,
				"Read %d bytes from RNG seed file\n", opt);
		}
	}

	if (regex) {
		vcp = vg_regex_context_new(addrtype, privtype);

	} else {
		vcp = vg_prefix_context_new(addrtype, privtype,
					    caseinsensitive);
	}

	vcp->vc_compressed = compressed;
	vcp->vc_verbose = verbose;
	vcp->vc_result_file = result_file;
	vcp->vc_remove_on_match = remove_on_match;
	vcp->vc_only_one = only_one;
	vcp->vc_numpairs = numpairs;
	vcp->vc_csv = csv;
	vcp->vc_pubkeytype = addrtype;
	vcp->vc_pubkey_base = pubkey_base;
	memcpy(vcp->vc_privkey_prefix, privkey_prefix, privkey_prefix_length);
	vcp->vc_privkey_prefix_length = privkey_prefix_length;

	vcp->vc_output_match = vg_output_match_console;
	vcp->vc_output_timing = vg_output_timing_console;

	if (!npattfp) {
		if (optind >= argc) {
			usage(argv[0]);
			return 1;
		}
		patterns = &argv[optind];
		npatterns = argc - optind;

		if (!vg_context_add_patterns(vcp,
					     (const char ** const) patterns,
					     npatterns))
		return 1;
	}

	for (i = 0; i < npattfp; i++) {
		fp = pattfp[i];
		if (!vg_read_file(fp, &patterns, &npatterns)) {
			fprintf(stderr, "Failed to load pattern file\n");
			return 1;
		}
		if (fp != stdin)
			fclose(fp);

		if (!regex)
			vg_prefix_context_set_case_insensitive(vcp, pattfpi[i]);

		if (!vg_context_add_patterns(vcp,
					     (const char ** const) patterns,
					     npatterns))
		return 1;
	}

	if (!vcp->vc_npatterns) {
		fprintf(stderr, "No patterns to search\n");
		return 1;
	}

	if (prompt_password) {
		if (!vg_read_password(pwbuf, sizeof(pwbuf)))
			return 1;
		key_password = pwbuf;
	}
	vcp->vc_key_protect_pass = key_password;
	if (key_password) {
		if (!vg_check_password_complexity(key_password, verbose))
			fprintf(stderr,
				"WARNING: Protecting private keys with "
				"weak password\n");
	}

	if ((verbose > 0) && regex && (vcp->vc_npatterns > 1))
		fprintf(stderr,
			"Regular expressions: %ld\n", vcp->vc_npatterns);

	if (ndevstrs) {
		for (opt = 0; opt < ndevstrs; opt++) {
			vocp = vg_ocl_context_new_from_devstr(vcp, devstrs[opt],
							      safe_mode,
							      verify_mode);
			if (!vocp) {
				fprintf(stderr,
				"Could not open device '%s', ignoring\n",
					devstrs[opt]);
			} else {
				opened++;
			}
		}
	} else {
		vocp = vg_ocl_context_new(vcp, platformidx, deviceidx,
					  safe_mode, verify_mode,
					  worksize, nthreads,
					  nrows, ncols, invsize);
		if (vocp)
			opened++;
	}

	if (!opened) {
		vg_ocl_enumerate_devices();
		return 1;
	}

	opt = vg_context_start_threads(vcp);
	if (opt)
		return 1;

	vg_context_wait_for_completion(vcp);
	vg_ocl_context_free(vocp);
	return 0;
}
