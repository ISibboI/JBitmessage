/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.twofish;

import de.flexiprovider.api.BlockCipher;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeySpec;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.util.LittleEndianConversions;

/**
 * This class implements the Twofish block cipher. For more information, <a
 * href=
 * "http://csrc.nist.gov/encryption/aes/round2/AESAlgs/Twofish/twofish.pdf">see
 * here</a>. For more information about this implementation see: Diploma thesis
 * "Implementierung von symmetrischen Verschluesselungsverfahren" by Katja
 * Rauch. Twofish uses a block size of 16 bytes. The key size can be 128, 192,
 * or 256 bits. Encryption/decryption takes 32 rounds.
 * 
 * @author Katja Rauch
 */
public class Twofish extends BlockCipher {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "Twofish";

	/**
	 * The Twofish block size (16 bytes)
	 */
	public static final int blockSize = 16;

	// the key array
	private int[] K = new int[40];

	// the S-Box
	private int[] S = new int[4];

	// holds key size / 64
	private int k;

	private static final byte[] q0 = { (byte) 169, (byte) 103, (byte) 179,
			(byte) 232, (byte) 4, (byte) 253, (byte) 163, (byte) 118,
			(byte) 154, (byte) 146, (byte) 128, (byte) 120, (byte) 228,
			(byte) 221, (byte) 209, (byte) 56, (byte) 13, (byte) 198,
			(byte) 53, (byte) 152, (byte) 24, (byte) 247, (byte) 236,
			(byte) 108, (byte) 67, (byte) 117, (byte) 55, (byte) 38,
			(byte) 250, (byte) 19, (byte) 148, (byte) 72, (byte) 242,
			(byte) 208, (byte) 139, (byte) 48, (byte) 132, (byte) 84,
			(byte) 223, (byte) 35, (byte) 25, (byte) 91, (byte) 61, (byte) 89,
			(byte) 243, (byte) 174, (byte) 162, (byte) 130, (byte) 99,
			(byte) 1, (byte) 131, (byte) 46, (byte) 217, (byte) 81, (byte) 155,
			(byte) 124, (byte) 166, (byte) 235, (byte) 165, (byte) 190,
			(byte) 22, (byte) 12, (byte) 227, (byte) 97, (byte) 192,
			(byte) 140, (byte) 58, (byte) 245, (byte) 115, (byte) 44,
			(byte) 37, (byte) 11, (byte) 187, (byte) 78, (byte) 137,
			(byte) 107, (byte) 83, (byte) 106, (byte) 180, (byte) 241,
			(byte) 225, (byte) 230, (byte) 189, (byte) 69, (byte) 226,
			(byte) 244, (byte) 182, (byte) 102, (byte) 204, (byte) 149,
			(byte) 3, (byte) 86, (byte) 212, (byte) 28, (byte) 30, (byte) 215,
			(byte) 251, (byte) 195, (byte) 142, (byte) 181, (byte) 233,
			(byte) 207, (byte) 191, (byte) 186, (byte) 234, (byte) 119,
			(byte) 57, (byte) 175, (byte) 51, (byte) 201, (byte) 98,
			(byte) 113, (byte) 129, (byte) 121, (byte) 9, (byte) 173,
			(byte) 36, (byte) 205, (byte) 249, (byte) 216, (byte) 229,
			(byte) 197, (byte) 185, (byte) 77, (byte) 68, (byte) 8, (byte) 134,
			(byte) 231, (byte) 161, (byte) 29, (byte) 170, (byte) 237,
			(byte) 6, (byte) 112, (byte) 178, (byte) 210, (byte) 65,
			(byte) 123, (byte) 160, (byte) 17, (byte) 49, (byte) 194,
			(byte) 39, (byte) 144, (byte) 32, (byte) 246, (byte) 96,
			(byte) 0xff, (byte) 150, (byte) 92, (byte) 177, (byte) 171,
			(byte) 158, (byte) 156, (byte) 82, (byte) 27, (byte) 95,
			(byte) 147, (byte) 10, (byte) 239, (byte) 145, (byte) 133,
			(byte) 73, (byte) 238, (byte) 45, (byte) 79, (byte) 143, (byte) 59,
			(byte) 71, (byte) 135, (byte) 109, (byte) 70, (byte) 214,
			(byte) 62, (byte) 105, (byte) 100, (byte) 42, (byte) 206,
			(byte) 203, (byte) 47, (byte) 252, (byte) 151, (byte) 5,
			(byte) 122, (byte) 172, (byte) 127, (byte) 213, (byte) 26,
			(byte) 75, (byte) 14, (byte) 167, (byte) 90, (byte) 40, (byte) 20,
			(byte) 63, (byte) 41, (byte) 136, (byte) 60, (byte) 76, (byte) 2,
			(byte) 184, (byte) 218, (byte) 176, (byte) 23, (byte) 85,
			(byte) 31, (byte) 138, (byte) 125, (byte) 87, (byte) 199,
			(byte) 141, (byte) 116, (byte) 183, (byte) 196, (byte) 159,
			(byte) 114, (byte) 126, (byte) 21, (byte) 34, (byte) 18, (byte) 88,
			(byte) 7, (byte) 153, (byte) 52, (byte) 110, (byte) 80, (byte) 222,
			(byte) 104, (byte) 101, (byte) 188, (byte) 219, (byte) 248,
			(byte) 200, (byte) 168, (byte) 43, (byte) 64, (byte) 220,
			(byte) 254, (byte) 50, (byte) 164, (byte) 202, (byte) 16,
			(byte) 33, (byte) 240, (byte) 211, (byte) 93, (byte) 15, (byte) 0,
			(byte) 111, (byte) 157, (byte) 54, (byte) 66, (byte) 74, (byte) 94,
			(byte) 193, (byte) 224 };

	private static final byte[] q1 = { (byte) 117, (byte) 243, (byte) 198,
			(byte) 244, (byte) 219, (byte) 123, (byte) 251, (byte) 200,
			(byte) 74, (byte) 211, (byte) 230, (byte) 107, (byte) 69,
			(byte) 125, (byte) 232, (byte) 75, (byte) 214, (byte) 50,
			(byte) 216, (byte) 253, (byte) 55, (byte) 113, (byte) 241,
			(byte) 225, (byte) 48, (byte) 15, (byte) 248, (byte) 27,
			(byte) 135, (byte) 250, (byte) 6, (byte) 63, (byte) 94, (byte) 186,
			(byte) 174, (byte) 91, (byte) 138, (byte) 0, (byte) 188,
			(byte) 157, (byte) 109, (byte) 193, (byte) 177, (byte) 14,
			(byte) 128, (byte) 93, (byte) 210, (byte) 213, (byte) 160,
			(byte) 132, (byte) 7, (byte) 20, (byte) 181, (byte) 144, (byte) 44,
			(byte) 163, (byte) 178, (byte) 115, (byte) 76, (byte) 84,
			(byte) 146, (byte) 116, (byte) 54, (byte) 81, (byte) 56,
			(byte) 176, (byte) 189, (byte) 90, (byte) 252, (byte) 96,
			(byte) 98, (byte) 150, (byte) 108, (byte) 66, (byte) 247,
			(byte) 16, (byte) 124, (byte) 40, (byte) 39, (byte) 140, (byte) 19,
			(byte) 149, (byte) 156, (byte) 199, (byte) 36, (byte) 70,
			(byte) 59, (byte) 112, (byte) 202, (byte) 227, (byte) 133,
			(byte) 203, (byte) 17, (byte) 208, (byte) 147, (byte) 184,
			(byte) 166, (byte) 131, (byte) 32, (byte) 0xff, (byte) 159,
			(byte) 119, (byte) 195, (byte) 204, (byte) 3, (byte) 111, (byte) 8,
			(byte) 191, (byte) 64, (byte) 231, (byte) 43, (byte) 226,
			(byte) 121, (byte) 12, (byte) 170, (byte) 130, (byte) 65,
			(byte) 58, (byte) 234, (byte) 185, (byte) 228, (byte) 154,
			(byte) 164, (byte) 151, (byte) 126, (byte) 218, (byte) 122,
			(byte) 23, (byte) 102, (byte) 148, (byte) 161, (byte) 29,
			(byte) 61, (byte) 240, (byte) 222, (byte) 179, (byte) 11,
			(byte) 114, (byte) 167, (byte) 28, (byte) 239, (byte) 209,
			(byte) 83, (byte) 62, (byte) 143, (byte) 51, (byte) 38, (byte) 95,
			(byte) 236, (byte) 118, (byte) 42, (byte) 73, (byte) 129,
			(byte) 136, (byte) 238, (byte) 33, (byte) 196, (byte) 26,
			(byte) 235, (byte) 217, (byte) 197, (byte) 57, (byte) 153,
			(byte) 205, (byte) 173, (byte) 49, (byte) 139, (byte) 1, (byte) 24,
			(byte) 35, (byte) 221, (byte) 31, (byte) 78, (byte) 45, (byte) 249,
			(byte) 72, (byte) 79, (byte) 242, (byte) 101, (byte) 142,
			(byte) 120, (byte) 92, (byte) 88, (byte) 25, (byte) 141,
			(byte) 229, (byte) 152, (byte) 87, (byte) 103, (byte) 127,
			(byte) 5, (byte) 100, (byte) 175, (byte) 99, (byte) 182,
			(byte) 254, (byte) 245, (byte) 183, (byte) 60, (byte) 165,
			(byte) 206, (byte) 233, (byte) 104, (byte) 68, (byte) 224,
			(byte) 77, (byte) 67, (byte) 105, (byte) 41, (byte) 46, (byte) 172,
			(byte) 21, (byte) 89, (byte) 168, (byte) 10, (byte) 158,
			(byte) 110, (byte) 71, (byte) 223, (byte) 52, (byte) 53,
			(byte) 106, (byte) 207, (byte) 220, (byte) 34, (byte) 201,
			(byte) 192, (byte) 155, (byte) 137, (byte) 212, (byte) 237,
			(byte) 171, (byte) 18, (byte) 162, (byte) 13, (byte) 82,
			(byte) 187, (byte) 2, (byte) 47, (byte) 169, (byte) 215, (byte) 97,
			(byte) 30, (byte) 180, (byte) 80, (byte) 4, (byte) 246, (byte) 194,
			(byte) 22, (byte) 37, (byte) 134, (byte) 86, (byte) 85, (byte) 9,
			(byte) 190, (byte) 145 };

	private static final int[] MDS = { -1128517003, -320069133, 538985414,
			-1280062988, -623246373, 33721211, -488494085, -1633748280,
			-909513654, -724301357, 404253670, 505323371, -1734865339,
			-1296942979, -1499016472, 640071499, 1010587606, -1819047374,
			-2105348392, 1381144829, 2071712823, -1145358479, 1532729329,
			1195869153, 606354480, 1364320783, -1162164488, 1246425883,
			-1077983097, 218984698, -1330597114, 1970658879, -757924514,
			2105352378, 1717973422, 976921435, 1499012234, 0, -842165316,
			437969053, -1364317075, 2139073473, 724289457, -1094797042,
			-522149760, -1970663331, 993743570, 1684323029, -656897888,
			-404249212, 1600120839, 454758676, 741130933, -50547568, 825304876,
			-2139069021, 1936927410, 202146163, 2037997388, 1802191188,
			1263207058, 1397975412, -1802203338, -2088558767, 707409464,
			-993747792, 572704957, -707397542, -1111636996, 1212708960, -12702,
			1280051094, 1094809452, -943200702, -336911113, 471602192,
			1566401404, 909517352, 1734852647, -370561140, 1145370899,
			336915093, -168445028, -808511289, 1061104932, -1061100730,
			1920129851, 1414818928, 690572490, -252693021, 134807173,
			-960096309, -202158319, -1936923440, -1532733037, -892692808,
			1751661478, -1195881085, 943204384, -437965057, -1381149025,
			185304183, -926409277, -1717960756, 1482222851, 421108335,
			235801096, -1785364801, 1886408768, -134795033, 1852755755,
			522153698, -1246413447, 151588620, 1633760426, 1465325186,
			-1616966847, -1650622406, 286352618, 623234489, -1347428892,
			1162152090, -538997340, -1549575017, -353708674, 892688602,
			-303181702, 1128528919, -117912730, -67391084, 926405537,
			-84262883, -1027446723, -1263219472, 842161630, -1667468877,
			1448535819, -471606670, -2021171033, 353704732, -101106961,
			1667481553, 875866451, -1701149378, -1313783153, 2088554803,
			-2004313306, 1027450463, -1583228948, -454762634, -2122214358,
			-1852767927, 252705665, -286348664, 370565614, -673746143,
			-1751648828, -1515870182, -16891925, 1835906521, 2021174981,
			-976917191, 488498585, 1987486925, 1044307117, -875862223,
			-1229568117, -269526271, 303177240, 1616954659, 1785376989,
			1296954911, -825300658, -555844563, 1431674361, 2122209864,
			555856463, 50559730, -1600117147, 1583225230, 1515873912,
			1701137244, 1650609752, -33733351, 101119117, 1077970661,
			-218972520, 859024471, 387420263, 84250239, -387424763, 1330609508,
			-1987482961, 269522275, 1953771446, 168457726, 1549570805,
			-1684310857, 757936956, 808507045, 774785486, 1229556201,
			1179021928, 2004309316, -1465329440, -1768553395, 673758531,
			-1448531607, -640059095, -2038001362, -774797396, -185316843,
			-1920133799, -690584920, -1179010038, 1111625118, -151600786,
			791656519, -572717345, 589510964, -859020747, -235813782,
			-1044311345, -2054820900, -1886413278, 1903272393, -1869549376,
			-1431678053, 16904585, -1953766956, 1313770733, -1903267925,
			-1414815214, 1869561506, -421112819, -606342574, -1835893829,
			-1212697086, 1768540719, 960092585, -741143337, -1482218655,
			-1566397154, -1010591308, 1819034704, 117900548, 67403766,
			656885442, -1397971178, -791644635, 1347425158, -589498538,
			-2071717291, -505327351, 2054825406, 320073617, -1445381831,
			1737496343, -1284399972, -388847962, 67438343, -40349102,
			-1553629056, 1994384612, -1710734011, -1845343413, -2136940320,
			2019973722, -455233617, -575640982, -775986333, 943073834,
			223667942, -968679392, 895667404, -1732316430, 404623890,
			-148575253, -321412703, 1819754817, 1136470056, 1966259388,
			936672123, 647727240, -93319923, 335103044, -1800274949,
			1213890174, -226884861, -790328180, -1958234442, 809247780,
			-2069501977, 1413573483, -553198115, 600137824, 424017405,
			1537423930, 1030275778, 1494584717, -215880468, -1372494234,
			-1572966545, -2112465065, 1670713360, 22802415, -2092058440,
			781289094, -642421395, 1361019779, -1689015638, 2086886749,
			-1506056088, -348127490, -1512689616, -1104840070, 380087468,
			202311945, -483004176, 1629726631, -1057976176, -1934628375,
			981507485, -174957476, 1937837068, 740766001, 628543696, 199710294,
			-1149529454, 1323945678, -1980694271, 1805590046, 1403597876,
			1791291889, -1264991293, -241738917, -511490233, -429189096,
			-1110957534, 1158584472, -496099553, -188107853, -1238403980,
			1724643576, -855664231, -1779821548, 65886296, 1459084508,
			-723416181, 471536917, 514695842, -687025197, -81009950,
			-1021458232, -1910940066, -1245565908, -376878775, -820854335,
			-1082223211, -1172275843, -362540783, 2005142283, 963495365,
			-1351972471, 869366908, -912166543, 1657733119, 1899477947,
			-2114253041, 2034087349, 156361185, -1378075074, 606945087,
			-844859786, -107129515, -655457662, -444186560, -978421640,
			-1177737947, 1292146326, 1146451831, 134876686, -2045554608,
			-416221193, -1579993289, 490797818, -1439407775, -309572018,
			112439472, 1886147668, -1305840781, -766362821, 1091280799,
			2072707586, -1601644328, 290452467, 828885963, -1035589849,
			666920807, -1867186948, 539506744, -159448060, 1618495560,
			-13703707, -1777906612, 1548445029, -1312347349, -1418752370,
			-1643298238, -1665403403, 1391647707, 468929098, 1604730173,
			-1822841692, 180140473, -281347591, -1846602989, -2046949368,
			1224839569, -295627242, 763158238, 1337073953, -1891454543,
			1004237426, 1203253039, -2025275457, 1831644846, 1189331136,
			-698926020, 1048943258, 1764338089, 1685933903, 714375553,
			-834064850, -887634234, 801794409, -54280771, -1755536477,
			90106088, 2060512749, -1400385071, 2140013829, -709204892,
			447260069, 1270294054, 247054014, -1486846073, 1526257109,
			673330742, 336665371, 1071543669, 695851481, -2002063634,
			1009986861, 1281325433, 45529015, -1198077238, -631753419,
			-1331903292, 402408259, 1427801220, 536235341, -1977853607,
			2100867762, 1470903091, -954675249, -1913387514, 1953059667,
			-1217094757, -990537833, -1621709395, 1926947811, 2127948522,
			357233908, 580816783, 312650667, 1481532002, 132669279,
			-1713038051, 876159779, 1858205430, 1346661484, -564317646,
			1752319558, 1697030304, -1131164211, -620504358, -121193798,
			-923099490, -1467820330, 735014510, 1079013488, -588544635,
			-25884150, 847942547, -1534205985, -900978391, 269753372,
			561240023, -255019852, -754330412, 1561365130, 266490193, 0,
			1872369945, -1646257638, 915379348, 1122420679, 1257032137,
			1593692882, -1045725313, -522671960, -1133134798, -319558623,
			549855299, -1275808823, -623126013, 41616011, -486809045,
			-1631019270, -917845524, -724315127, 417732715, 510336671,
			-1740269554, -1300385224, -1494702382, 642459319, 1020673111,
			-1825401974, -2099739922, 1392333464, 2067233748, -1150174409,
			1542544279, 1205946243, 607134780, 1359958498, -1158104378,
			1243302643, -1081622712, 234491248, -1341738829, 1967093214,
			-765537539, 2109373728, 1722705457, 979057315, 1502239004, 0,
			-843264621, 446503648, -1368543700, 2143387563, 733031367,
			-1106329927, -528424800, -1973581296, 1003633490, 1691706554,
			-660547448, -410720347, 1594318824, 454302481, 750070978,
			-57606988, 824979751, -2136768411, 1941074730, 208866433,
			2035054943, 1800694593, 1267878658, 1400132457, -1808362353,
			-2091810017, 708323894, -995048292, 582820552, -715467272,
			-1107509821, 1214269560, -10289202, 1284918279, 1097613687,
			-951924762, -336073948, 470817812, 1568431459, 908604962,
			1730635712, -376641105, 1142113529, 345314538, -174262853,
			-808988904, 1059340077, -1069104925, 1916498651, 1416647788,
			701114700, -253497291, 142936318, -959724009, -216927409,
			-1932489500, -1533828007, -893859178, 1755736123, -1199327155,
			941635624, -436214482, -1382044330, 192351108, -926693347,
			-1714644481, 1476614381, 426711450, 235408906, -1782606466,
			1883271248, -135792848, 1848340175, 534912878, -1250314947,
			151783695, 1638555956, 1468159766, -1623089397, -1657102976,
			300552548, 632890829, -1343967267, 1167738120, -542842995,
			-1550343332, -360781099, 903492952, -310710832, 1125598204,
			-127469365, -74122319, 933312467, -98698688, -1036139928,
			-1259293492, 853422685, -1665950607, 1443583719, -479009830,
			-2019063968, 354161947, -101713606, 1674666943, 877868201,
			-1707173243, -1315983038, 2083749073, -2010740581, 1029651878,
			-1578327593, -461970209, -2127920748, -1857449727, 260116475,
			-293015894, 384702049, -685648013, -1748723723, -1524980312,
			-18088385, 1842965941, 2026207406, -986069651, 496573925,
			1993176740, 1051541212, -885929113, -1232357817, -285085861,
			303567390, 1612931269, 1792895664, 1293897206, -833696023,
			-567419268, 1442403741, 2118680154, 558834098, 66192250,
			-1603952602, 1586388505, 1517836902, 1700554059, 1649959502,
			-48628411, 109905652, 1088766086, -224857410, 861352876, 392632208,
			92210574, -402266018, 1331974013, -1984984726, 274927765,
			1958114351, 184420981, 1559583890, -1682465932, 758918451,
			816132310, 785264201, 1240025481, 1181238898, 2000975701,
			-1461671720, -1773300220, 675489981, -1452693207, -651568775,
			-2043771247, -777203321, -199887798, -1923511019, -693578110,
			-1190479428, 1117667853, -160500031, 793194424, -572531450,
			590619449, -868889502, -244649532, -1043349230, -2049145365,
			-1893560418, 1909027233, -1866428176, -1432638893, 25756145,
			-1949004831, 1324174988, -1901359505, -1424839774, 1872916286,
			-435296684, -615326734, -1833201029, -1224558666, 1764714954,
			967391705, -740830452, -1486772445, -1575050579, -1011563623,
			1817209924, 117704453, 83231871, 667035462, -1407800153,
			-802828170, 1350979603, -598287113, -2074770406, -519446191,
			2059303461, 328274927, -650532391, -1877514352, 1906094961,
			-760813358, 84345861, -1739391592, 1702929253, -538675489,
			138779144, 38507010, -1595899744, 1717205094, -575675171,
			-1335173712, -1083977281, 908736566, 1424362836, 1126221379,
			1657550178, -1091397442, 504502302, 619444004, -677253929,
			2000776311, -1121434691, 851211570, -730122284, -1685576037,
			1879964272, -112978951, -1308912463, 1518225498, 2047079034,
			-460533532, 1203145543, 1009004604, -1511553883, 1097552961,
			115203846, -983555131, 1174214981, -1556456541, 1757560168,
			361584917, 569176865, 828812849, 1047503422, 374833686,
			-1794088043, 1542390107, 1303937869, -1853477231, -1251092043,
			528699679, 1403689811, 1667071075, 996714043, 1073670975,
			-701454890, 628801061, -1481894233, 252251151, 904979253,
			598171939, -258948880, -1343648593, -2137179520, -1839401582,
			-2129890431, 657533991, 1993352566, -413791257, 2073213819,
			-372355351, -251557391, -1625396321, -1456188503, -990811452,
			-1715227495, -1755582057, -2092441213, 1796793963, -937247288,
			244860174, 1847583342, -910953271, 796177967, -872913205, -6697729,
			-367749654, -312998931, -136554761, -510929695, 454368283,
			-1381884243, 215209740, 736295723, 499696413, 425627161,
			-1037257278, -1991644791, 314691346, 2123743102, 545110560,
			1678895716, -2079623292, 1841641837, 1787408234, -780389423,
			-1586378335, -822123826, 935031095, -82869765, 1035303229,
			1373702481, -599872036, 759112749, -1535717980, -1655309923,
			-293414674, -2042567290, -1367816786, -853165619, 76958980,
			1433879637, 168691722, 324044307, 821552944, -751328813,
			1090133312, 878815796, -1940984436, -1280309581, 1817473132,
			712225322, 1379652178, 194986251, -1962771573, -1999069048,
			1341329743, 1741369703, 1177010758, -1066981440, -1258516300,
			674766888, 2131031679, 2018009208, 786825006, 122459655,
			1264933963, -953437753, 1871620975, 222469645, -1141531461,
			-220507406, -213246989, -1505927258, 1503957849, -1128723780,
			989458234, -283930129, -32995842, 26298625, 1628892769, 2094935420,
			-1306439758, 1118932802, -613270565, -1204861000, 1220511560,
			749628716, -473938205, 1463604823, -2053489019, 698968361,
			2102355069, -1803474284, 1227804233, 398904087, -899076150,
			-1010959165, 1554224988, 1592264030, -789742896, -2016301945,
			-1912242290, -1167796806, -1465574744, -1222227017, -1178726727,
			1619502944, -120235272, 573974562, 286987281, -562741282,
			2044275065, -1427208022, 858602547, 1601784927, -1229520202,
			-1765099370, 1479924312, -1664831332, -62711812, 444880154,
			-162717706, 475630108, 951221560, -1405921364, 416270104,
			-200897036, 1767076969, 1956362100, -174603019, 1454219094,
			-622628134, -706052395, 1257510218, -1634786658, -1565846878,
			1315067982, -396425240, -451044891, 958608441, -1040814399,
			1147949124, 1563614813, 1917216882, 648045862, -1815233389,
			64674563, -960825146, -90257158, -2099861374, -814863409,
			1349533776, -343548693, 1963654773, -1970064758, -1914723187,
			1277807180, 337383444, 1943478643, -860557108, 164942601,
			277503248, -498003998, 0, -1709609062, -535126560, -1886112113,
			-423148826, -322352404, -36544771, -1417690709, -660021032 };

	private int[] mdsExp = new int[1024];

	/**
	 * @return the name of this cipher
	 */
	public String getName() {
		return ALG_NAME;
	}

	/**
	 * Return the key size of the given key object. Checks whether the key
	 * object is an instance of <tt>TwofishKey</tt> and whether the key size is
	 * within the specified range for Twofish. 128, 192, and 256 bit keys are
	 * allowed.
	 * 
	 * @param key
	 *            the key object
	 * @return the key size of the given key object.
	 * @throws InvalidKeyException
	 *             if key is invalid.
	 */
	public int getKeySize(Key key) throws InvalidKeyException {
		if (!((key instanceof TwofishKey) || (key instanceof SecretKeySpec))) {
			throw new InvalidKeyException("not a Twofish Key");
		}

		int keyLen = key.getEncoded().length;

		// check key size
		if (keyLen != 16 && keyLen != 24 && keyLen != 32) {
			throw new InvalidKeyException("invalid key size");
		}

		return keyLen << 3;
	}

	/**
	 * This method returns the blocksize the algorithm uses. It will be called
	 * by the padding scheme.
	 * 
	 * @return the used blocksize in <B>bytes</B>
	 */
	public int getCipherBlockSize() {
		return blockSize;
	}

	/**
	 * Initializes the block cipher with a secret key for data encryption. The
	 * algorithm parameters are not used.
	 * 
	 * @param key
	 *            the encryption key
	 * @param params
	 *            the parameters (not used)
	 * @throws InvalidKeyException
	 *             if the given key is <tt>null</tt> or not an instance of
	 *             {@link TwofishKey}.
	 */
	protected void initCipherEncrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException {
		if ((key == null) || !(key instanceof TwofishKey)) {
			throw new InvalidKeyException("wrong type");
		}
		keyExpansion(key.getEncoded());
	}

	/**
	 * Initialize the block cipher with a secret key for data encryption. The
	 * algorithm parameters are not used.
	 * 
	 * @param key
	 *            the decryption key
	 * @param params
	 *            the parameters (not used)
	 * @throws InvalidKeyException
	 *             if the given key is <tt>null</tt> or not an instance of
	 *             {@link TwofishKey}.
	 */
	protected void initCipherDecrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException {
		initCipherEncrypt(key, params);
	}

	/**
	 * This method implements the Twofish key expansion.
	 * 
	 * @param key
	 *            An array of bytes contaning the key data
	 */
	private void keyExpansion(byte[] key) {

		k = key.length >> 3;

		// convert input bytes to ints
		int[] Me = new int[k];
		int[] Mo = new int[k];

		for (int i = 0, offset = 0; i < k; i++, offset += 8) {
			Me[i] = LittleEndianConversions.OS2IP(key, offset);
			Mo[i] = LittleEndianConversions.OS2IP(key, offset + 4);
		}

		// assign values to the S-Box
		for (int l = 0; l < k; l++) {
			S[k - l - 1] = Mo[l];
			for (int j = 0; j < 4; j++) {
				S[k - l - 1] = (S[k - l - 1] << 8)
						^ mul((S[k - l - 1] >>> 24) & 0xff);
			}
			S[k - l - 1] ^= Me[l];
			for (int j = 0; j < 4; j++) {
				S[k - l - 1] = (S[k - l - 1] << 8)
						^ mul((S[k - l - 1] >>> 24) & 0xff);
			}
		}

		// assign values to the key array
		final int p = 0x01010101;
		for (int i = 0; i < 20; i++) {
			// call the h_perm-function
			int A = hPerm((i << 1) * p, Me);
			int B = hPerm(((i << 1) + 1) * p, Mo);
			B = leftRotateBy8(B);
			K[i << 1] = A + B;
			A += B << 1;
			K[(i << 1) + 1] = (A << 9) | (A >>> 23);
		}

		// assign values to the MDSexp array
		for (int l = 0; l < 256; l++) {
			int y0 = l;
			int y1 = l;
			int y2 = l;
			int y3 = l;

			// check if key size = 32 bytes
			if (k == 4) {
				y0 = (q1[y0] ^ S[3]) & 0xff;
				y1 = (q0[y1] ^ (S[3] >>> 8)) & 0xff;
				y2 = (q0[y2] ^ (S[3] >>> 16)) & 0xff;
				y3 = (q1[y3] ^ (S[3] >>> 24)) & 0xff;
			}

			// check if key size >= 24 bytes
			if (k >= 3) {
				y0 = (q1[y0] ^ S[2]) & 0xff;
				y1 = (q1[y1] ^ (S[2] >>> 8)) & 0xff;
				y2 = (q0[y2] ^ (S[2] >>> 16)) & 0xff;
				y3 = (q0[y3] ^ (S[2] >>> 24)) & 0xff;
			}

			y0 = (q0[(q0[y0] ^ S[1]) & 0xff] ^ S[0]) & 0xff;
			y1 = (q0[(q1[y1] ^ (S[1] >>> 8)) & 0xff] ^ (S[0] >>> 8)) & 0xff;
			y2 = (q1[(q0[y2] ^ (S[1] >>> 16)) & 0xff] ^ (S[0] >>> 16)) & 0xff;
			y3 = (q1[(q1[y3] ^ (S[1] >>> 24)) & 0xff] ^ (S[0] >>> 24)) & 0xff;

			mdsExp[l] = MDS[y0];
			mdsExp[256 + l] = MDS[256 + y1];
			mdsExp[512 + l] = MDS[512 + y2];
			mdsExp[768 + l] = MDS[768 + y3];
		}
	}

	/**
	 * This method encrypts a single block of data. The array <TT>in</TT> must
	 * contain a whole block starting at <TT>inOffset</TT> and <TT>out</TT> must
	 * be large enough to hold an encrypted block starting at <TT>outOffset</TT>
	 * .
	 * 
	 * @param input
	 *            array of bytes containing the plaintext to be encrypted
	 * @param inOff
	 *            index in array in, where the plaintext block starts
	 * @param output
	 *            array of bytes which will contain the ciphertext starting at
	 *            outOffset
	 * @param outOff
	 *            index in array out, where the ciphertext block will start
	 */
	protected void singleBlockEncrypt(byte[] input, int inOff, byte[] output,
			int outOff) {

		// convert input bytes to ints
		int d0 = LittleEndianConversions.OS2IP(input, inOff);
		int d1 = LittleEndianConversions.OS2IP(input, inOff + 4);
		int d2 = LittleEndianConversions.OS2IP(input, inOff + 8);
		int d3 = LittleEndianConversions.OS2IP(input, inOff + 12);

		// XOR keys and data
		d0 ^= K[0];
		d1 ^= K[1];
		d2 ^= K[2];
		d3 ^= K[3];

		// 16 transformation rounds
		int l = 8;
		for (int i = 0; i < 16; i += 2) {
			// call the h-function
			int t0 = hExp(d0);
			int t1 = hExp(leftRotateBy8(d1));
			d2 ^= t0 + t1 + K[l++];
			d2 = rightRotateBy1(d2);
			d3 = leftRotateBy1(d3) ^ (t0 + (t1 << 1) + K[l++]);

			// call the h-function
			t0 = hExp(d2);
			t1 = hExp(leftRotateBy8(d3));
			d0 ^= t0 + t1 + K[l++];
			d0 = rightRotateBy1(d0);
			d1 = leftRotateBy1(d1) ^ (t0 + (t1 << 1) + K[l++]);
		}

		// XOR keys and data
		d2 ^= K[4];
		d3 ^= K[5];
		d0 ^= K[6];
		d1 ^= K[7];

		// convert ints to output bytes
		LittleEndianConversions.I2OSP(d2, output, outOff);
		LittleEndianConversions.I2OSP(d3, output, outOff + 4);
		LittleEndianConversions.I2OSP(d0, output, outOff + 8);
		LittleEndianConversions.I2OSP(d1, output, outOff + 12);
	}

	/**
	 * This method decrypts a single block of data. The array <TT>in</TT> must
	 * contain a whole block starting at <TT>inOffset</TT> and <TT>out</TT> must
	 * be large enough to hold an encrypted block starting at <TT>outOffset</TT>
	 * .
	 * 
	 * @param input
	 *            array of bytes containig the ciphertext to be decrypted
	 * @param inOff
	 *            index in array in, where the ciphertext block starts
	 * @param output
	 *            array of bytes which will contain the plaintext starting at
	 *            outOffset
	 * @param outOff
	 *            index in array out, where the plaintext block will start
	 */

	protected void singleBlockDecrypt(byte[] input, int inOff, byte[] output,
			int outOff) {

		// convert input bytes to ints
		int d2 = LittleEndianConversions.OS2IP(input, inOff);
		int d3 = LittleEndianConversions.OS2IP(input, inOff + 4);
		int d0 = LittleEndianConversions.OS2IP(input, inOff + 8);
		int d1 = LittleEndianConversions.OS2IP(input, inOff + 12);

		// XOR keys and data
		d2 ^= K[4];
		d3 ^= K[5];
		d0 ^= K[6];
		d1 ^= K[7];

		// 16 transformation rounds
		int l = 39;
		for (int i = 0; i < 16; i = i + 2) {
			// call the h-function
			int t0 = hExp(d2);
			int t1 = hExp(leftRotateBy8(d3));
			d1 ^= t0 + (t1 << 1) + K[l--];
			d1 = rightRotateBy1(d1);
			d0 = leftRotateBy1(d0) ^ (t0 + t1 + K[l--]);

			// call the h-function
			t0 = hExp(d0);
			t1 = hExp(leftRotateBy8(d1));
			d3 ^= t0 + (t1 << 1) + K[l--];
			d3 = rightRotateBy1(d3);
			d2 = leftRotateBy1(d2) ^ (t0 + t1 + K[l--]);
		}

		// XOR keys and data
		d0 ^= K[0];
		d1 ^= K[1];
		d2 ^= K[2];
		d3 ^= K[3];

		// convert ints to output bytes
		LittleEndianConversions.I2OSP(d0, output, outOff);
		LittleEndianConversions.I2OSP(d1, output, outOff + 4);
		LittleEndianConversions.I2OSP(d2, output, outOff + 8);
		LittleEndianConversions.I2OSP(d3, output, outOff + 12);
	}

	/**
	 * This method implements the Twofish h_perm function.
	 * 
	 * @param x
	 *            integer value
	 * @param S
	 *            integer array
	 */

	private int hPerm(int x, int[] S) {

		// separate the bytes of the input word
		int y0 = x & 0xff;
		int y1 = (x >>> 8) & 0xff;
		int y2 = (x >>> 16) & 0xff;
		int y3 = (x >>> 24) & 0xff;

		// check if key size = 32 bytes
		if (k == 4) {
			y0 = (q1[y0] ^ S[3]) & 0xff;
			y1 = (q0[y1] ^ (S[3] >>> 8)) & 0xff;
			y2 = (q0[y2] ^ (S[3] >>> 16)) & 0xff;
			y3 = (q1[y3] ^ (S[3] >>> 24)) & 0xff;
		}

		// check if key size >= 24 bytes
		if (k >= 3) {
			y0 = (q1[y0] ^ S[2]) & 0xff;
			y1 = (q1[y1] ^ (S[2] >>> 8)) & 0xff;
			y2 = (q0[y2] ^ (S[2] >>> 16)) & 0xff;
			y3 = (q0[y3] ^ (S[2] >>> 24)) & 0xff;
		}

		y0 = (q0[(q0[y0] ^ S[1]) & 0xff] ^ S[0]) & 0xff;
		y1 = (q0[(q1[y1] ^ (S[1] >>> 8)) & 0xff] ^ (S[0] >>> 8)) & 0xff;
		y2 = (q1[(q0[y2] ^ (S[1] >>> 16)) & 0xff] ^ (S[0] >>> 16)) & 0xff;
		y3 = (q1[(q1[y3] ^ (S[1] >>> 24)) & 0xff] ^ (S[0] >>> 24)) & 0xff;

		// XOR the MDS array values
		return MDS[y0] ^ MDS[256 + y1] ^ MDS[512 + y2] ^ MDS[768 + y3];
	}

	/**
	 * This method implements the Twofish expanded h function used in
	 * singleBlockEncrypt and singleBlockDecrypt
	 * 
	 * @param x
	 *            integer value
	 */
	private int hExp(int x) {
		// separate the bytes of the input word
		int y0 = x & 0xff;
		int y1 = (x >>> 8) & 0xff;
		int y2 = (x >>> 16) & 0xff;
		int y3 = (x >>> 24) & 0xff;

		// XOR the MDSexp array values
		return mdsExp[y0] ^ mdsExp[256 + y1] ^ mdsExp[512 + y2]
				^ mdsExp[768 + y3];
	}

	/**
	 * This method implements the function
	 * <tt>g(x) = x<sup>4</sup> + (a+(1/a))*x<sup>3</sup> + a*x<sup>2</sup> + (a+(1/a))*x + 1</tt>
	 * .
	 * 
	 * @param x
	 *            the argument of the function
	 * @return <tt>g(x)</tt>
	 */
	private static int mul(int x) {

		int coef2 = x << 1;
		if ((coef2 & 0x100) != 0) {
			coef2 ^= 333;
		}

		int coef3;
		if ((x & 0x01) != 0) {
			coef3 = (x ^ 333) >>> 1;
		} else {
			coef3 = x >>> 1;
		}
		coef3 ^= coef2;
		return (coef3 << 24) ^ (coef3 << 8) ^ (coef2 << 16) ^ x;
	}

	private static int leftRotateBy1(int data) {
		return (data << 1) | (data >>> 31);
	}

	private static int leftRotateBy8(int data) {
		return (data << 8) | (data >>> 24);
	}

	private static int rightRotateBy1(int data) {
		return (data >>> 1) | (data << 31);
	}

}
