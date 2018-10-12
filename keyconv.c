#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#if !defined(_WIN32)
#include <unistd.h>
#else
#include "winglue.h"
#endif

#include "pattern.h"
#include "util.h"
#include "ticker.h"
char ticker[10];

const char *version = VANITYGEN_VERSION;

int GRSFlag = 0;

static void
usage(const char *progname)
{
	fprintf(stderr,
"Vanitygen keyconv %s\n"
"Usage: %s [-8] [-e|-E <password>] [-c <key>] [<key>]\n"
"-G            Generate a key pair and output the full public key\n"
"-8            Output key in PKCS#8 form\n"
"-F <format>   Output address in the given format (compressed)\n"
"-e            Encrypt output key, prompt for password\n"
"-E <password> Encrypt output key with <password> (UNSAFE)\n"
"-c <key>      Combine private key parts to make complete private key\n"
"-C <altcoin>  Decrypt an address for specific altcoin, use \"-C LIST\" to view\n"
"              a list of all available altcoins, argument is case sensitive!\n"
"-d            Decrypt output key, prompt for password\n"
"-X <version>  Public key version (for altcoins)\n"
"-Y <version>  Private key version (-X provides public key)\n"
"-v            Verbose output\n",
		version, progname);
}


int
main(int argc, char **argv)
{
	char pwbuf[128];
	char ecprot[128];
	char pbuf[1024];
	const char *key_in;
	const char *pass_in = NULL;
	const char *key2_in = NULL;
	EC_KEY *pkey;
	int parameter_group = -1;
	int addrtype = 0;
	int privtype = 128;
	int addrtype_opt = addrtype;
	int privtype_opt = privtype;
	int addrtype_override = 0;
	int pkcs8 = 0;
	int pass_prompt = 0;
	int compressed = 0;
	int verbose = 0;
	int generate = 0;
	int decrypt = 0;
	int opt;
	int res;

	while ((opt = getopt(argc, argv, "C:8E:ec:vGX:Y:dF:")) != -1) {
		switch (opt) {
/*BEGIN ALTCOIN GENERATOR*/

		case 'C':
			strcpy(ticker, optarg);
			strcat(ticker, " ");
			addrtype_override = 1;
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
					"AXE : Axe : P\n"
					"BLAST : BLAST : B\n"
					"BLK : Blackcoin : B\n"
					"BWK : Bulwark : b\n"
					"BQC : BBQcoin : b\n"
					"BTC : Bitcoin : 1\n"
					"TEST : Bitcoin Testnet : m or n\n"
					"BTCD : Bitcoin Dark : R\n"
					"CARE : Carebit : C\n"
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
					"EXCL : Exclusivecoin : E\n"
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
					"JBS : Jumbucks : J\n"
					"JIN : Jincoin : J\n"
					"KMD : Komodo (and assetchains) : R\n"
					"KORE : Kore : K\n"
					"LBRY : LBRY : b\n"
					"LEAF : Leafcoin : f\n"
					"LMC : LomoCoin : L\n"
					"LTC : Litecoin : L\n"
					"MMC : Memorycoin : M\n"
					"MNP : MNPCoin : M\n"
					"MOG : Mogwai : M\n"
					"MONA : Monacoin : M\n"
					"MUE : Monetary Unit : 7\n"
					"MYRIAD : Myriadcoin : M\n"
					"MZC : Mazacoin : M\n"
					"NEOS : Neoscoin : S\n"
					"NLG : Gulden : G\n"
					"NEET : NEETCOIN : N\n"
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
					addrtype_opt = 53;
					privtype_opt = 181;
					break;
			}
			else
			if (strcmp(optarg, "PIVX")== 0) {
				fprintf(stderr,
					"Generating PIVX Address\n");
					addrtype_opt = 30;
					privtype_opt = 212;
					break;
			}
			else
			if (strcmp(optarg, "KMD")== 0) {
				fprintf(stderr,
					"Generating KMD Address\n");
					addrtype_opt = 60;
					privtype_opt = 188;
					break;
			}
			else
			if (strcmp(optarg, "PINK")== 0) {
				fprintf(stderr,
					"Decrypting PINK Address\n");
					addrtype_opt = 3;
					privtype_opt = 131;
					break;
			}
			else
			if (strcmp(optarg, "DEEPONION")== 0) {
				fprintf(stderr,
					"Decrypting DEEPONION Address\n");
					addrtype_opt = 31;
					privtype_opt = 159;
					break;
			}
			else
			if (strcmp(optarg, "DNR")== 0) {
				fprintf(stderr,
					"Decrypting DNR Address\n");
					addrtype_opt = 30;
					privtype_opt = 158;
					break;
			}
			else
			if (strcmp(optarg, "DMD")== 0) {
				fprintf(stderr,
					"Decrypting DMD Address\n");
					addrtype_opt = 90;
					privtype_opt = 218;
					break;
			}
			else
			if (strcmp(optarg, "GUN")== 0) {
				fprintf(stderr,
					"Decrypting GUN Address\n");
					addrtype_opt = 39;
					privtype_opt = 167;
					break;
			}
			else
			if (strcmp(optarg, "HAM")== 0) {
				fprintf(stderr,
					"Decrypting HAM Address\n");
					addrtype_opt = 0;
					privtype_opt = 128;
					break;
			}
			else
			if (strcmp(optarg, "DVC")== 0) {
				fprintf(stderr,
					"Decrypting DVC Address\n");
					addrtype_opt = 0;
					privtype_opt = 128;
					break;
			}
			else
			if (strcmp(optarg, "42")== 0) {
				fprintf(stderr,
					"Decrypting 42 Address\n");
					addrtype_opt = 8;
					privtype_opt = 136;
					break;
			}
			else
			if (strcmp(optarg, "WKC")== 0) {
				fprintf(stderr,
					"Decrypting WKC Address\n");
					addrtype_opt = 0;
					privtype_opt = 128;
					break;
			}
			else
			if (strcmp(optarg, "SPR")== 0) {
				fprintf(stderr,
					"Decrypting SPR Address\n");
					addrtype_opt = 63;
					privtype_opt = 191;
					break;
			}
			else
			if (strcmp(optarg, "SCA")== 0) {
				fprintf(stderr,
					"Decrypting SCA Address\n");
					addrtype_opt = 63;
					privtype_opt = 191;
					break;
			}
			else
			if (strcmp(optarg, "GAP")== 0) {
				fprintf(stderr,
					"Decrypting GAP Address\n");
					addrtype_opt = 38;
					privtype_opt = 166;
					break;
			}
			else
			if (strcmp(optarg, "CCC")== 0) {
				fprintf(stderr,
					"Decrypting CCC Address\n");
					addrtype_opt = 15;
					privtype_opt = 224;
					break;
			}
			else
			if (strcmp(optarg, "PIGGY")== 0) {
				fprintf(stderr,
					"Decrypting PIGGY Address\n");
					addrtype_opt = 118;
					privtype_opt = 246;
					break;
			}
			else
			if (strcmp(optarg, "WDC")== 0) {
				fprintf(stderr,
					"Decrypting WDC Address\n");
					addrtype_opt = 73;
					privtype_opt = 201;
					break;
			}
			else
			if (strcmp(optarg, "EMC")== 0) {
				fprintf(stderr,
						"Decrypting Emercoin Address\n");
				addrtype_opt = 33;
				privtype_opt = 128;
				break;
			}
			else
			if (strcmp(optarg, "EXCL")== 0) {
				fprintf(stderr,
					"Decrypting EXCL Address\n");
					addrtype_opt = 33;
					privtype_opt = 161;
					break;
			}
			else
			if (strcmp(optarg, "XC")== 0) {
				fprintf(stderr,
					"Decrypting XC Address\n");
					addrtype_opt = 75;
					privtype_opt = 203;
					break;
			}
			else
			if (strcmp(optarg, "WUBS")== 0) {
				fprintf(stderr,
					"Decrypting WUBS Address\n");
					addrtype_opt = 29;
					privtype_opt = 157;
					break;
			}
			else
			if (strcmp(optarg, "SXC")== 0) {
				fprintf(stderr,
					"Decrypting SXC Address\n");
					addrtype_opt = 62;
					privtype_opt = 190;
					break;
			}
			else
			if (strcmp(optarg, "SKC")== 0) {
				fprintf(stderr,
					"Decrypting SKC Address\n");
					addrtype_opt = 63;
					privtype_opt = 226;
					break;
			}
			else
			if (strcmp(optarg, "PTS")== 0) {
				fprintf(stderr,
					"Decrypting PTS Address\n");
					addrtype_opt = 56;
					privtype_opt = 184;
					break;
			}
			else
			if (strcmp(optarg, "NLG")== 0) {
				fprintf(stderr,
					"Decrypting NLG Address\n");
					addrtype_opt = 38;
					privtype_opt = 166;
					break;
			}
			else
			if (strcmp(optarg, "MMC")== 0) {
				fprintf(stderr,
					"Decrypting MMC Address\n");
					addrtype_opt = 50;
					privtype_opt = 178;
					break;
			}
			else
			if (strcmp(optarg, "LEAF")== 0) {
				fprintf(stderr,
					"Decrypting LEAF Address\n");
					addrtype_opt = 95;
					privtype_opt = 223;
					break;
			}
			else
			if (strcmp(optarg, "HODL")== 0) {
				fprintf(stderr,
					"Decrypting HODL Address\n");
					addrtype_opt = 40;
					privtype_opt = 168;
					break;
			}
			else
			if (strcmp(optarg, "ROI")== 0) {
				fprintf(stderr,
					"Decrypting ROI Address\n");
					addrtype_opt = 60;
					privtype_opt = 128;
					break;
			}
			else
			if (strcmp(optarg, "FLOZ")== 0) {
				fprintf(stderr,
					"Decrypting FLOZ Address\n");
					addrtype_opt = 35;
					privtype_opt = 163;
					break;
			}
			else
			if (strcmp(optarg, "FAIR")== 0) {
				fprintf(stderr,
					"Decrypting FAIR Address\n");
					addrtype_opt = 95;
					privtype_opt = 223;
					break;
			}
			else
			if (strcmp(optarg, "CON")== 0) {
				fprintf(stderr,
					"Decrypting CON Address\n");
					addrtype_opt = 55;
					privtype_opt = 183;
					break;
			}
			else
			if (strcmp(optarg, "AUR")== 0) {
				fprintf(stderr,
					"Decrypting AUR Address\n");
					addrtype_opt = 23;
					privtype_opt = 151;
					break;
			}
			else
			if (strcmp(optarg, "GRC")== 0) {
				fprintf(stderr,
					"Decrypting GRC Address\n");
					addrtype_opt = 62;
					privtype_opt = 190;
					break;
			}
			else
			if (strcmp(optarg, "RIC")== 0) {
				fprintf(stderr,
					"Decrypting RIC Address\n");
					addrtype_opt = 60;
					privtype_opt = 128;
					break;
			}
			else
			if (strcmp(optarg, "UNO")== 0) {
				fprintf(stderr,
					"Decrypting UNO Address\n");
					addrtype_opt = 130;
					privtype_opt = 224;
					break;
			}
			else
			if (strcmp(optarg, "UIS")== 0) {
				fprintf(stderr,
					"Decrypting UIS Address\n");
					addrtype_opt = 68;
					privtype_opt = 132;
					break;
			}
			else
			if (strcmp(optarg, "MYRIAD")== 0) {
				fprintf(stderr,
					"Decrypting MYRIAD Address\n");
					addrtype_opt = 50;
					privtype_opt = 178;
					break;
			}
			else
			if (strcmp(optarg, "BQC")== 0) {
				fprintf(stderr,
					"Decrypting BQC Address\n");
					addrtype_opt = 85;
					privtype_opt = 213;
					break;
			}
			else
			if (strcmp(optarg, "YAC")== 0) {
				fprintf(stderr,
					"Decrypting YAC Address\n");
					addrtype_opt = 77;
					privtype_opt = 205;
					break;
			}
			else
			if (strcmp(optarg, "PTC")== 0) {
				fprintf(stderr,
					"Decrypting PTC Address\n");
					addrtype_opt = 47;
					privtype_opt = 175;
					break;
			}
			else
			if (strcmp(optarg, "RDD")== 0) {
				fprintf(stderr,
					"Decrypting RDD Address\n");
					addrtype_opt = 61;
					privtype_opt = 189;
					break;
			}
			else
			if (strcmp(optarg, "NYAN")== 0) {
				fprintf(stderr,
					"Decrypting NYAN Address\n");
					addrtype_opt = 45;
					privtype_opt = 173;
					break;
			}
			else
			if (strcmp(optarg, "IXC")== 0) {
				fprintf(stderr,
					"Decrypting IXC Address\n");
					addrtype_opt = 138;
					privtype_opt = 266;
					break;
			}
			else
			if (strcmp(optarg, "CNC")== 0) {
				fprintf(stderr,
					"Decrypting CNC Address\n");
					addrtype_opt = 28;
					privtype_opt = 156;
					break;
			}
			else
			if (strcmp(optarg, "CNOTE")== 0) {
				fprintf(stderr,
					"Decrypting C-Note Address\n");
					addrtype_opt = 28;
					privtype_opt = 186;
					break;
			}
			else
			if (strcmp(optarg, "ARS")== 0) {
				fprintf(stderr,
					"Decrypting ARS Address\n");
					addrtype_opt = 23;
					privtype_opt = 151;
					break;
			}
			else
			if (strcmp(optarg, "ANC")== 0) {
				fprintf(stderr,
					"Decrypting ANC Address\n");
					addrtype_opt = 23;
					privtype_opt = 151;
					break;
			}
			else
			if (strcmp(optarg, "OMC")== 0) {
				fprintf(stderr,
					"Decrypting OMC Address\n");
					addrtype_opt = 115;
					privtype_opt = 243;
					break;
			}
			else
			if (strcmp(optarg, "POT")== 0) {
				fprintf(stderr,
					"Decrypting POT Address\n");
					addrtype_opt = 55;
					privtype_opt = 183;
					break;
			}
			else
			if (strcmp(optarg, "EFL")== 0) {
				fprintf(stderr,
					"Decrypting EFL Address\n");
					addrtype_opt = 48;
					privtype_opt = 176;
					break;
			}
			else
			if (strcmp(optarg, "DOGED")== 0) {
				fprintf(stderr,
					"Decrypting DOGED Address\n");
					addrtype_opt = 30;
					privtype_opt = 158;
					break;
			}
			else
			if (strcmp(optarg, "OK")== 0) {
				fprintf(stderr,
					"Decrypting OK Address\n");
					addrtype_opt = 55;
					privtype_opt = 183;
					break;
			}
			else
			if (strcmp(optarg, "AIB")== 0) {
				fprintf(stderr,
					"Decrypting AIB Address\n");
					addrtype_opt = 23;
					privtype_opt = 151;
					break;
			}
			else
			if (strcmp(optarg, "TPC")== 0) {
				fprintf(stderr,
					"Decrypting TPC Address\n");
					addrtype_opt = 65;
					privtype_opt = 193;
					break;
			}
			else
			if (strcmp(optarg, "DOPE")== 0) {
				fprintf(stderr,
					"Decrypting DOPE Address\n");
					addrtype_opt = 8;
					privtype_opt = 136;
					break;
			}
			else
			if (strcmp(optarg, "BTCD")== 0) {
				fprintf(stderr,
					"Decrypting BTCD Address\n");
					addrtype_opt = 60;
					privtype_opt = 188;
					break;
			}
			else
			if (strcmp(optarg, "AC")== 0) {
				fprintf(stderr,
					"Decrypting AC Address\n");
					addrtype_opt = 23;
					privtype_opt = 151;
					break;
			}
			else
			if (strcmp(optarg, "NVC")== 0) {
				fprintf(stderr,
					"Decrypting NVC Address\n");
					addrtype_opt = 8;
					privtype_opt = 136;
					break;
			}
			else
			if (strcmp(optarg, "HBN")== 0) {
				fprintf(stderr,
					"Decrypting HBN Address\n");
					addrtype_opt = 34;
					privtype_opt = 162;
					break;
			}
			else
			if (strcmp(optarg, "GCR")== 0) {
				fprintf(stderr,
					"Decrypting GCR Address\n");
					addrtype_opt = 38;
					privtype_opt = 154;
					break;
			}
			else
			if (strcmp(optarg, "START")== 0) {
				fprintf(stderr,
					"Decrypting START Address\n");
					addrtype_opt = 125;
					privtype_opt = 253;
					break;
			}
			else
			if (strcmp(optarg, "PND")== 0) {
				fprintf(stderr,
					"Decrypting PND Address\n");
					addrtype_opt = 55;
					privtype_opt = 183;
					break;
			}
			else
			if (strcmp(optarg, "PKB")== 0) {
				fprintf(stderr,
					"Decrypting PKB Address\n");
					addrtype_opt = 55;
					privtype_opt = 183;
					break;
			}
			else
			if (strcmp(optarg, "SDC")== 0) {
				fprintf(stderr,
					"Decrypting SDC Address\n");
					addrtype_opt = 63;
					privtype_opt = 191;
					break;
			}
			else
			if (strcmp(optarg, "CDN")== 0) {
				fprintf(stderr,
					"Decrypting CDN Address\n");
					addrtype_opt = 28;
					privtype_opt = 156;
					break;
			}
			else
			if (strcmp(optarg, "VPN")== 0) {
				fprintf(stderr,
					"Decrypting VPN Address\n");
					addrtype_opt = 71;
					privtype_opt = 199;
					break;
			}
			else
			if (strcmp(optarg, "ZOOM")== 0) {
				fprintf(stderr,
					"Decrypting ZOOM Address\n");
					addrtype_opt = 103;
					privtype_opt = 231;
					break;
			}
			else
			if (strcmp(optarg, "MUE")== 0) {
				fprintf(stderr,
					"Decrypting MUE Address\n");
					addrtype_opt = 15;
					privtype_opt = 143;
					break;
			}
			else
			if (strcmp(optarg, "VTC")== 0) {
				fprintf(stderr,
					"Decrypting VTC Address\n");
					addrtype_opt = 71;
					privtype_opt = 199;
					break;
			}
			else
			if (strcmp(optarg, "ZRC")== 0) {
				fprintf(stderr,
					"Decrypting ZRC Address\n");
					addrtype_opt = 80;
					privtype_opt = 208;
					break;
			}
			else
			if (strcmp(optarg, "JBS")== 0) {
				fprintf(stderr,
					"Decrypting JBS Address\n");
					addrtype_opt = 43;
					privtype_opt = 171;
					break;
			}
			else
			if (strcmp(optarg, "JIN")== 0) {
				fprintf(stderr,
					"Decrypting JIN Address\n");
					addrtype_opt = 43;
					privtype_opt = 171;
					break;
			}
			else
			if (strcmp(optarg, "NEOS")== 0) {
				fprintf(stderr,
					"Decrypting NEOS Address\n");
					addrtype_opt = 63;
					privtype_opt = 239;
					break;
			}
			else
			if (strcmp(optarg, "XPM")== 0) {
				fprintf(stderr,
					"Decrypting XPM Address\n");
					addrtype_opt = 23;
					privtype_opt = 151;
					break;
			}
			else
			if (strcmp(optarg, "CLAM")== 0) {
				fprintf(stderr,
					"Decrypting CLAM Address\n");
					addrtype_opt = 137;
					privtype_opt = 133;
					break;
			}
			else
			if (strcmp(optarg, "MONA")== 0) {
				fprintf(stderr,
					"Decrypting MONA Address\n");
					addrtype_opt = 50;
					privtype_opt = 176;
					break;
			}
			else
			if (strcmp(optarg, "DGB")== 0) {
				fprintf(stderr,
					"Decrypting DGB Address\n");
					addrtype_opt = 30;
					privtype_opt = 128;
					break;
			}
			else
			if (strcmp(optarg, "CCN")== 0) {
				fprintf(stderr,
					"Decrypting CCN Address\n");
					addrtype_opt = 28;
					privtype_opt = 156;
					break;
			}
			else
			if (strcmp(optarg, "DGC")== 0) {
				fprintf(stderr,
					"Decrypting DGC Address\n");
					addrtype_opt = 30;
					privtype_opt = 158;
					break;
			}
			else
			if (strcmp(optarg, "GRS")== 0) {
				fprintf(stderr,
					"Decrypting GRS Address\n");
					GRSFlag = 1;
					addrtype_opt = 36;
					privtype_opt = 128;
					break;
			}
			else
			if (strcmp(optarg, "RBY")== 0) {
				fprintf(stderr,
					"Decrypting RBY Address\n");
					addrtype_opt = 61;
					privtype_opt = 189;
					break;
			}
			else
			if (strcmp(optarg, "VIA")== 0) {
				fprintf(stderr,
					"Decrypting VIA Address\n");
					addrtype_opt = 71;
					privtype_opt = 199;
					break;
			}
			else
			if (strcmp(optarg, "MZC")== 0) {
				fprintf(stderr,
					"Decrypting MZC Address\n");
					addrtype_opt = 50;
					privtype_opt = 224;
					break;
			}
			else
			if (strcmp(optarg, "BLAST")== 0) {
				fprintf(stderr,
					"Decrypting BLAST Address\n");
					addrtype_opt = 25;
					privtype_opt = 239;
					break;
			}
			else
			if (strcmp(optarg, "BLK")== 0) {
				fprintf(stderr,
					"Decrypting BLK Address\n");
					addrtype_opt = 25;
					privtype_opt = 153;
					break;
			}
			else
			if (strcmp(optarg, "FTC")== 0) {
				fprintf(stderr,
					"Decrypting FTC Address\n");
					addrtype_opt = 14;
					privtype_opt = 142;
					break;
			}
			else
			if (strcmp(optarg, "PPC")== 0) {
				fprintf(stderr,
					"Decrypting PPC Address\n");
					addrtype_opt = 55;
					privtype_opt = 183;
					break;
			}
			else
			if (strcmp(optarg, "DASH")== 0) {
				fprintf(stderr,
					"Decrypting DASH Address\n");
					addrtype_opt = 76;
					privtype_opt = 204;
					break;
			}
			else
			if (strcmp(optarg, "MOG")== 0) {
				fprintf(stderr,
					"Decrypting Mogwai Address\n");
					addrtype_opt = 50;
					privtype_opt = 204;
					break;
			}
			else
			if (strcmp(optarg, "BTC")== 0) {
				fprintf(stderr,
					"Decrypting BTC Address\n");
					addrtype_opt = 0;
					privtype_opt = 128;
					break;
			}
			else
			if (strcmp(optarg, "IC")== 0) {
				fprintf(stderr,
					"Decrypting IC Address\n");
					addrtype_opt = 103;
					privtype_opt = 138;
					break;
			}
			else
			if (strcmp(optarg, "TEST")== 0) {
				fprintf(stderr,
					"Decrypting BTC Testnet Address\n");
					addrtype_opt = 111;
					privtype_opt = 239;
					break;
			}
			else
			if (strcmp(optarg, "DOGE")== 0) {
				fprintf(stderr,
					"Decrypting DOGE Address\n");
					addrtype_opt = 30;
					privtype_opt = 158;
					break;
			}
			else
			if (strcmp(optarg, "LBRY")== 0) {
				fprintf(stderr,
					"Decrypting LBRY Address\n");
					addrtype_opt = 85;
					privtype_opt = 28;
					break;
			}
			else
			if (strcmp(optarg, "LMC")== 0) {
				fprintf(stderr,
					"Decrypting LomoCoin Address\n");
					addrtype_opt = 48;
					privtype_opt = 176;
					break;
			}
			else
			if (strcmp(optarg, "LTC")== 0) {
				fprintf(stderr,
					"Decrypting LTC Address\n");
					addrtype_opt = 48;
					privtype_opt = 176;
					break;
			}
			else
			if (strcmp(optarg, "GRLC")== 0) {
				fprintf(stderr,
					"Decrypting GRLC Address\n");
					addrtype_opt = 38;
					privtype_opt = 176;
					break;
			}
			else
			if (strcmp(optarg, "GRN")== 0) {
				fprintf(stderr,
					"Decrypting GRN Address\n");
					addrtype_opt = 38;
					privtype_opt = 166;
					break;
			}
			else
			if (strcmp(optarg, "BWK")== 0) {
				fprintf(stderr,
					"Decrypting BWK Address\n");
					addrtype_opt = 85;
					privtype_opt = 212;
					break;
			}
			else
			if (strcmp(optarg, "NMC")== 0) {
				fprintf(stderr,
					"Decrypting NMC Address\n");
					addrtype_opt = 52;
					privtype_opt = 180;
					break;
			}
			else
			if (strcmp(optarg, "GAME")== 0) {
				fprintf(stderr,
					"Decrypting GAME Address\n");
					addrtype_opt = 38;
					privtype_opt = 166;
					break;
			}
			else
			if (strcmp(optarg, "CRW")== 0) {
				fprintf(stderr,
					"Decrypting CRW Address\n");
					addrtype_opt = 0;
					privtype_opt = 128;
					break;
			}
			else
			if (strcmp(optarg, "QTUM")== 0) {
				fprintf(stderr,
					"Decrypting QTUM Address\n");
					addrtype_opt = 58;
					privtype_opt = 128;
					break;
			}
			else
			if (strcmp(optarg, "ATMOS")== 0) {
				fprintf(stderr,
					"Decrypting ATMOS Address\n");
					addrtype_opt = 53;
					privtype_opt = 153;
					break;
			}
			else
			if (strcmp(optarg, "AXE")== 0) {
				fprintf(stderr,
					"Decrypting Axe Address\n");
					addrtype_opt = 55;
					privtype_opt = 204;
					break;
			}
			else
			if (strcmp(optarg, "ZNY")== 0) {
				fprintf(stderr,
					"Decrypting BitZeny Address\n");
					addrtype_opt = 81;
					privtype_opt = 128;
					break;
			}
			else
			if (strcmp(optarg, "NEET")== 0) {
				fprintf(stderr,
					"Decrypting NEETCOIN Address\n");
					addrtype_opt = 53;
					privtype_opt = 181;
					break;
			}
			else
			if (strcmp(optarg, "YTN")== 0) {
				fprintf(stderr,
					"Decrypting Yenten Address\n");
					addrtype_opt = 78;
					privtype_opt = 123;
					break;
			}
			else
			if (strcmp(optarg, "RVN")== 0) {
				fprintf(stderr,
					"Decrypting Ravencoin Address\n");
					addrtype_opt = 60;
					privtype_opt = 128;
					break;
			}
			else
			if (strcmp(optarg, "VIPS")== 0) {
				fprintf(stderr,
					"Decrypting VIPSTARCOIN Address\n");
					addrtype_opt = 70;
					privtype_opt = 128;
					break;
			}
			else
			if (strcmp(optarg, "CIV")== 0) {
				fprintf(stderr,
					"Decrypting Civitas Address\n");
					addrtype_opt = 28;
					privtype_opt = 212;
					break;
			}
			else
			if (strcmp(optarg, "tCIV")== 0) {
				fprintf(stderr,
					"Decrypting Civitas Testnet Address\n");
					addrtype_opt = 139;
					privtype_opt = 239;
					break;
			}
			else
			if (strcmp(optarg, "GRV")== 0) {
				fprintf(stderr,
					"Decrypting Gravium Address\n");
					addrtype_opt = 38;
					privtype_opt = 166;
					break;
			}
			else
			if (strcmp(optarg, "MNP")== 0) {
				fprintf(stderr,
					"Decrypting MNPCoin Address\n");
					addrtype_opt = 50;
					privtype_opt = 55;
					break;
			}
			else
			if (strcmp(optarg, "CARE")== 0) {
				fprintf(stderr,
					"Decrypting Carebit Address\n");
					addrtype_opt = 28;
					privtype_opt = 55;
					break;
			}
			else
			if (strcmp(optarg, "TUX")== 0) {
				fprintf(stderr,
					"Decrypting TUX Address\n");
					addrtype_opt = 65;
					privtype_opt = 193;
					break;
                        }
                        else
			if (strcmp(optarg, "KORE")== 0) {
				fprintf(stderr,
					"Decrypting Kore Address\n");
					addrtype_opt = 45;
					privtype_opt = 128;
					break;		
			}
			break;

/*END ALTCOIN GENERATOR*/
		case '8':
			pkcs8 = 1;
			break;
		case 'E':
			if (pass_prompt) {
				usage(argv[0]);
				return 1;
			}
			pass_in = optarg;
			if (!vg_check_password_complexity(pass_in, 1))
				fprintf(stderr,
					"WARNING: Using weak password\n");
			break;
		case 'e':
			if (pass_in) {
				usage(argv[0]);
				return 1;
			}
			pass_prompt = 1;
			break;
		case 'c':
			key2_in = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'G':
			generate = 1;
			break;
		case 'd':
			decrypt = 1;
			break;
		case 'X':
			addrtype_opt = atoi(optarg);
			privtype_opt = addrtype + 128;
			addrtype_override = 1;
			break;
		case 'Y':
			privtype_opt = atoi(optarg);
			addrtype_override = 1;
			break;
		case 'F':
                        if (!strcmp(optarg, "compressed")) {
                                compressed = 1;
			}
                        else {
				fprintf(stderr,
					"Invalid choice '%s'\n", optarg);
				return 1;
			}
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}
	if (addrtype_override)
	{
		addrtype = addrtype_opt;
		privtype = privtype_opt;
	}


	OpenSSL_add_all_algorithms();

	pkey = EC_KEY_new_by_curve_name(NID_secp256k1);

	if (generate) {
		unsigned char *pend = (unsigned char *) pbuf;
		EC_KEY_generate_key(pkey);
		res = i2o_ECPublicKey(pkey, &pend);
		fprintf(stderr, "Pubkey (hex): ");
		dumphex((unsigned char *)pbuf, res);
		fprintf(stderr, "Privkey (hex): ");
		dumpbn(EC_KEY_get0_private_key(pkey));
		vg_encode_address(EC_KEY_get0_public_key(pkey),
				  EC_KEY_get0_group(pkey),
				  addrtype, ecprot);
		printf("Address: %s\n", ecprot);
		vg_encode_privkey(pkey, privtype, ecprot);
		printf("Privkey: %s\n", ecprot);
		return 0;
	}

	if (optind >= argc) {
		res = fread(pbuf, 1, sizeof(pbuf) - 1, stdin);
		pbuf[res] = '\0';
		key_in = pbuf;
	} else {
		key_in = argv[optind];
	}

	if (decrypt) {
		if (EVP_read_pw_string(pwbuf, sizeof(pwbuf),
				       "Enter import password:", 0) ||
		    !vg_protect_decode_privkey(pkey, &privtype, key_in, pwbuf))
			return 1;
		res = 1;
	} else
		res = vg_decode_privkey_any(pkey, &privtype, key_in, NULL);

	if (!res) {
		fprintf(stderr, "ERROR: Unrecognized key format\n");
		return 1;
	}

	if (res == 2) {
		compressed = 1;
	}

	if (key2_in) {
		BN_CTX *bnctx;
		BIGNUM *bntmp, *bntmp2;
		EC_KEY *pkey2;

		pkey2 = EC_KEY_new_by_curve_name(NID_secp256k1);
		res = vg_decode_privkey_any(pkey2, &privtype, key2_in, NULL);
		if (res < 0) {
			if (EVP_read_pw_string(pwbuf, sizeof(pwbuf),
					       "Enter import password:", 0) ||
			    !vg_decode_privkey_any(pkey2, &privtype,
						   key2_in, pwbuf))
				return 1;
		}

		if (!res) {
			fprintf(stderr, "ERROR: Unrecognized key format\n");
			return 1;
		}

		if (res == 2) {
			compressed = 1;
		}

		bntmp = BN_new();
		bntmp2 = BN_new();
		bnctx = BN_CTX_new();
		EC_GROUP_get_order(EC_KEY_get0_group(pkey), bntmp2, NULL);
		BN_mod_add(bntmp,
			   EC_KEY_get0_private_key(pkey),
			   EC_KEY_get0_private_key(pkey2),
			   bntmp2,
			   bnctx);
		vg_set_privkey(bntmp, pkey);
		EC_KEY_free(pkey2);
		BN_clear_free(bntmp);
		BN_clear_free(bntmp2);
		BN_CTX_free(bnctx);
	}

	if (pass_prompt) {
		res = EVP_read_pw_string(pwbuf, sizeof(pwbuf),
					 "Enter password:", 1);
		if (res)
			return 1;
		pass_in = pwbuf;
		if (!vg_check_password_complexity(pwbuf, 1))
			fprintf(stderr, "WARNING: Using weak password\n");
	}

	if (addrtype_override)
	{
		addrtype = addrtype_opt;
		privtype = privtype_opt;
	}

	if (verbose) {
		unsigned char *pend = (unsigned char *) pbuf;
		res = i2o_ECPublicKey(pkey, &pend);
		fprintf(stderr, "Pubkey (hex): ");
		dumphex((unsigned char *)pbuf, res);
		fprintf(stderr, "Privkey (hex): ");
		dumpbn(EC_KEY_get0_private_key(pkey));
	}

	if (pkcs8) {
		res = vg_pkcs8_encode_privkey(pbuf, sizeof(pbuf),
					      pkey, pass_in);
		if (!res) {
			fprintf(stderr,
				"ERROR: Could not encode private key\n");
			return 1;
		}
		printf("%s", pbuf);
	}

	else if (pass_in) {
		res = vg_protect_encode_privkey(ecprot, pkey, privtype,
						parameter_group, pass_in);

		if (!res) {
			fprintf(stderr, "ERROR: could not password-protect "
				"private key\n");
			return 1;
		}

		vg_encode_address(EC_KEY_get0_public_key(pkey),
				  EC_KEY_get0_group(pkey),
				  addrtype, pwbuf);
		printf("Address: %s\n", pwbuf);
		printf("Protkey: %s\n", ecprot);
	}

	else {
		if (compressed) {
			vg_encode_address_compressed(EC_KEY_get0_public_key(pkey),
						     EC_KEY_get0_group(pkey),
						     addrtype, ecprot);
			printf("Address: %s\n", ecprot);
			vg_encode_privkey_compressed(pkey, privtype, ecprot);
			printf("Privkey: %s\n", ecprot);
		} else {
			vg_encode_address(EC_KEY_get0_public_key(pkey),
					  EC_KEY_get0_group(pkey),
					  addrtype, ecprot);
			printf("Address: %s\n", ecprot);
			vg_encode_privkey(pkey, privtype, ecprot);
			printf("Privkey: %s\n", ecprot);
		}
	}

	OPENSSL_cleanse(pwbuf, sizeof(pwbuf));

	EC_KEY_free(pkey);
	return 0;
}
