use strict;
use Digest::SHA3;

my $TAGS = join('|', qw(Len Msg Squeezed));
my @vecs = ();
while (<DATA>) {
	next unless /^\s*($TAGS)\s*=\s*([\dA-F]+)/o;
	push(@vecs, $2);
}

my $numtests = scalar(@vecs) / 3;
print "1..$numtests\n";

for (1 .. $numtests) {
	my $sha3 = Digest::SHA3->new(0);
	my $Len = shift @vecs;
	my $Msg = pack("H*", shift @vecs);
	my $Squeezed = shift @vecs;
	my $computed = $sha3->add_bits($Msg, $Len)->hexdigest;
	print "not " unless $computed eq lc($Squeezed);
	print "ok ", $_, "\n";
}

__DATA__
# ShortMsgKAT_0.txt
# Algorithm Name: Keccak
# Principal Submitter: The Keccak Team (Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche)

Len = 0
Msg = 00
Squeezed = 6753E3380C09E385D0339EB6B050A68F66CFD60A73476E6FD6ADEB72F5EDD7C6F04A5D017A19CBE291935855B4860F69DF04C98AA78B407A9BA9826F7266EF14BA6D3F90C4FE154D27C2858EA6DB8C117411A1BC5C499410C391B298F37BF636B0F5C31DBD6487A7D3D8CF2A97B619697E66D894299B8B4D80E0498538E18544C3A2FA33F0BFB1CFEF8DA7875C4967F332C7FC93C050E81FB404F9A91503D6010EE16F50B4ED0BC563BA8431668B003D7E2E6F226CB7FA93BB2E132C861FDC2141457589A63ECF05481126A7C2DE941A2FDEC71CB70DE81887B9014223865E79C4FFE82DAE83C1FC484B9A07A7E52B135F4AE3A0E09247EA4E2625E9349B0AC73F24CB418DF6DCB49CA37860298ADA18AA23595B5096EF789DE3EDF3826817FFF4F71102A01E1D2599F2958D5C186F5B11F5FEEDB61BB732DBB42D18B1E77258A8F211BF95C9F47F19603EC419FF879AEA41A4811344D016BBC4F9496741C469CCA425C5BE73543219AF40796C0B9FF14AEAA70C5E22E4BB1346A3DDFEDD8A559104E4704F1227D42918AE3F7404FBF3C6340A486E776AABCC34190F87DA4BD954B83386255A0E34DF05CA2E781FAF6FE66475852481FCE20798A56629ABFAC408760CE64606008A3B568C88ABA1C6DF3381E0765567EA84B2CE4B441CF1EEFAA32125D5139361A632B3008566A2E8AF1055CB06AE462B6BF87B34A9770618E6

Len = 1
Msg = 00
Squeezed = 3B26339B55D6032E33A202EB839A95C49809822AA56DBBDCB35F61073DADE57695D956B52FB279CFF89784190AB22F3703C1D8676EA61B0936C3B5AE2D5041ED3D859DA77618D649AC917CD8EF562465791EE1491BE9E7F81423CF9CDDE2CC152D0AA4746F4A3184E20F2F95FE870435DAAD1CAA21E55EC5BA5B22A62BAD5C2DC2B7646030A791B218093BAAFFA5BFDE0E5DA458F67B31F22D254B3AB8F980DA64E87A4B6916F8427BD15DCF9D68C75D1EF5623BD953AD5FC2A6E959B2D70ABA7C1C4B403409AF5F8A8625C63C660D9B24B45E3E22E64ABA248305257A2069B03C9A5C4084F99E472DCD1AA2DE05678607278269F71DB76EA9DD984C8A099C67E1430607D0EC27ADFAF10884A8C422CC56FE2A4935112D2DB7A79618AE826B28374C9FD1032632AE254394EB33F9D3A493C64C80FCA281CFECBD94762B83609C6891693113A4923E744974EB177E1D3A2861523664FB13C713D3B05D78EBAC543DC24C97493A0E5DD136EE5CB32787C2EE6FBAECC063AFC62085E0C5F9230761CC80A12E37F0D3D15028D5771444B56F9F008DBF2483B670A0F7AEFF88E854CD8C73AC69D7F2EC2453CC22BD3807715108471A6F63BA71768EF6FDB590F75B45EDA826C41C1AD953DAB1EF07D7DEFF73C5681E0C0EAAA3D69572EC367335DB8E1080DB5BCF952BA9EDD6743DF95A64152459EF279F997D41ABDCEEB913A30FA4

Len = 2
Msg = C0
Squeezed = BD1DAED8990F6277D3531AD6379C2B55C7B48364F6A936C7EFEED7DD5D6A2B954DD4212389134778C3D522C623444FB49A92CAE135EA071852B0175A9E6D4B4EE0A4022BD35F07F8BF1F558189377B1E72937EBFA6FA45FCBF8680A1D5F1C0E392A7DFAC13A4D0CA4057C10BBAE9277D06E78299D153AC71102CAFCE655F23FACED1EF896CCD0074D2BED8DD1137A750C654BDC89092EAE0C5D934E76E07F517D3020FEBD5103FCECA0999E2585823ADEDE5ED44B053FD7BADA35E065561451F096C2ADEAAFFF03E9EAFBBD6F57EEF3568E218E792B146362CAF1A400AA3D7E1707E700FB8B895B2CA0A7E7BC0521D8A51317CD05EB11E81B9868FB74F95BD1F9795857B9B4ABBEF137F95A587EF287F121FC0550A93ED6FBA7C7252DD8E81B2D6FCCB53C8ED4AA1177D09FC2C106B6CD346A46FAB567289A6CD427FA4A8B85375F109FA078E415D57683475DF000A2C306C6EBE15107E3BD1DAC2BA8020144B353534B66B7C0232086F849AF91A30459EE28BFAC3B02F4B042889C5334FBA60C5D962D22ACFAAB5AA7ABDFCB31ED87CB799C3EA8715BC5F5F438E7A8C8EEBE20F89AD73247768633B5C3272CD3345066472C353EA95DAE01581F5BF0CBE1B7DC8442A60C09DE546835A5A4B0A40E0B1DF09F280073571F8B0DB09D8CB1D38DCC395A9031012A7FB25D87E61E082A63F8BC8392B3827C6E674D97291737ECB94

Len = 3
Msg = C0
Squeezed = DF3F9748368136E205D689FFEF983E1BBFAAC8A6F794168214649D558546C35A7C196E1E88C3956CA9EA8A9777E996B009DB94CFBD910AF4FA57E89F5E22EDD81A9A8D93AED698BC7D2570579B3C76CD1A3091FAD3CA31DA1E3BB847BD1D2AA1FE6BAE7689D128169D575D86B17F99E16F3B3548BEF8E2048876415AE6F68EF9717761E731AEC991C524A49B3DD1D67B99F7F02E99E5FD31A0AB68495F9C1F150DFF4E98907B84AF1FEFA9D1E22724C88AEB33E5575DDD5DAFF2427DA382B18D32D26C533122F656FD2D31D678C66515BB1B0BC85314D7C0064628DA1A3D05D036BE69F274DC64CE45B350A19A3D9F087B638335232F5646C546DAB4822F88A31F877D287E1F62E16E78CFD21BB7DC9EC136C9F50325086503E254E0BFC0664EA44FF0E3284927BFD8B35078F60BFE54CECDA348B135E0C21D50B33DEE3FDC6E0AD1AAE95867AC766DE238599EDA02D8FD5E90A48542C4A39094C8EA8206701C759025058E4774D3E5126989D230A41D92F9C1027E546BA9C3B3323CDBB19AA9C0C36187F5CEBB162261A6B04E51F80DE7B3168A3978788C104A21DA0105A0F232B519C412BCB3E9A99EFCD91D34A92027DFFD0A47EF0539262B5EF60E75551130F5B78C3C21558A93B01CC16590B3EF361FE35499A436E58930D120D0E1BB72AB9356897DDCFE2FCD0845AFDAC8B74A8423083034E672507DE659A6543A01BC

Len = 4
Msg = 80
Squeezed = ED9F512A947F51866A497FA627F15884340860DBAE4877CE04FD853ACAA7A7B4CBA907F1237E1E3A06E60F10B82DDBBDF62DF1BB8059F7AC72F6A51E3D50FF911D8C2410D3A598C6B228F5E9C4C08202CADBD045914062A02766160D0815A6CB7906BE2A9AB9CE6DDA1E0FDD327CED60F16257F49DF5DB14AC6C4BEE559F1335137585FAB622DB916FBB7C7F4E5C54E93A75295ADD1B630EC83C7EE105B24FF06B72BA13AB8679276187597A307F13B3CEFAC3EC192A0976A0BE59EAAAD675ABA47FE9E8DA51A442BE792096521AA1A951D2EC54A439183B677D7E04AB01554671E2589E9098D4EA66BDF6E0AE4E3AB1A8BE544C9D31AB4827097918F20735906B0D1BC101F08E1DD7313E845BA7C1DF7A61E65B8751633A19FC86ACAF8449E1B711CA67762B8E020F2FBB0F1BAD975C347C391EC804E12D7676B16D44025FFE748E363C948E4627465AC2EEF1C02F2AF1A691EF498DC0A07AEFDFD0984A340DAB3FC3AF9ED85A44875FDBEA9831A43B10B904C92F53FCA94A0DC25170259B9A18DE67A8FCCFC85A7FBE295ABD074047B6F2DB44E2949D1A8FF2BA5DFF29694A64B1A8C0F9260FE6C0F8AC440D84AF8C045E20A6DBA660E7C6CFE125319A19435A90DB0AA21C9E93FC36491C37D645F138FC9624CD02AD22B00555BE5EC7FADFD6830065650B9E695B024D3A56D55775B768BBDEDFA31907C88095EF7BA8CFE6

Len = 5
Msg = 48
Squeezed = F40BC4762056332FE9207177DBBAAD5379B078E12362708A7B58F06C6E01669C63C743650E74958CFE3CD985F65792D063C8F86E3DB139B5E9B1CAAF1C6D0D55493CC28336BB3F1979411A1E0129AB28E7215A8E33B9511A32EAAA82FAF4F21C9CB154970F82E770240122135FA4F0AA5223CB4BA40396B5227B2C37914E67E0435A1AF24EE05715EE0C28936ADE00BF7367D27A462532C99B83E08558D1D18A37EC90580056B1A31139254C1E66745BAF7B31CA267E93C74DA79EF5851C36C0CFD9BB80622404ECA53F8D0573C962861E6BF0D1D5F699BE20B856529B1C6806569FDC1CA0793F0BCB4768901681AA7E771E533EE78F684FFC4950BAB6639412D7DA57BF29D8D399AB362BD8151BFEE63F14D191F244956A2433493EACC99D42D06B2BE9F8D56FAA4A4BAA4BF4AB0A2CD421BEFBD03B3BF0B97D23A1EECD680F7991DE5B980DD6890DE83543B80A173BE291C7999710D8DF32FE3F91ECE1285F58470DCECF88EB413A4C726A12226B804BD3E9BE43EECA4E170D733219467B4C96CE8D478F73D009DACFB72C6FDA6267F479BC0566B6D7E3E0C1D1DC2753862F4365E41D045A707DD52346608720F0C931BB896220D2B655E68BBB6D18B1924E8C081B02693EE509BD1D557162A959E60CF9D2CF0DB13C436EDEF1F03CCEC54C844BEE6D191E90140A398884E64FCAAA9FF80EAC7F06D7CC97DD47C6F2947E47

Len = 6
Msg = 50
Squeezed = 94956D2652417BAA8FA06B61089D2BD7F7ACB5C895F907A3AFFE1177122A5044D456B8F968112A0554C8A19736E7DB0CB4375B0D18F1B959B10A71A07BC48B114A2632CA9CC3C72C9A5034E9F7C58CC19A0ADC4CDBC10D6ECDDBFCDDF8C184FEEBE7DB2FE14DD99E74A222BA8777753A70915711D62F4E3499CD05A7B58F8120CA157E9E1F5F8DB731B745274F6F1DD9B863AD7F4C5E6C04C45AA68B49BB90D7F811E01739F7B2E5353CDB3BCBEA145DCA52386A02611C8A779675493E1663C19675C545AB2CBDCE7961714193710A536F4B8371608DF73C2844CC6EE42DC1684CDC2B3D4535758EA0F19600571BD713A194AB71F41AC8A8A34E48D1C341D6C50818D653F0AB85283B86E1DD63A1A88F8E49CA6B4F4A43211732CAA32EB091C885BA2F659BB44D77A3CBABF10A1A84FDF24C4350568FAE05B7251A545224ABC2A107A0A1C5B7EB1685E12B85B8E6A6A1E8275F9EA081887D70E91C0B9260108B9937833A349E1DBA1A2F8503803B8F83B04B4E6BB7859FA9CFB53BBC0D2E95E8C33D66D79FC4B49FB180C8303B884948160C75617B109B9F6A64D0E039D89C193154870564F84701B4003E58F74186EDF526287FF9383364923D14F9598B8610EEDE357F7825866D9C9840C3B0B361F87EC059B9238370DAA335FB8120FCE3B302E8E7B48134861C980B9BEC13885ACCB6F5C4789616537CEBC866A95B1CDCE1

Len = 7
Msg = 98
Squeezed = 8DFEAD0EDBB84B467B44CF57A6013F3CBD391D122FDC4E5416D2208A1F302C4B5F997B7D73F00DEBC36D12CA56339E6698A23BF02AED6660A1BDB9FE7FE0F01832FA14A2B8A2C91BB8A18D62AF7BD884F2A3CB449DEB61EEB1CEBA414708C0CA387EDDE746E4FBD4B4733983E6BA064D301A5B2CEDD3A2D0F9750B180548800533C81689F611B3C003100FE4387494B541DEC96DA396C07656DE5559C55976BE4102F6AEA6F8DA2783F3D7D998CDDFF105EEB1ABC4EA5EB754652904585F9B131A083D952AE1EBE8DC17BDD8334FCEA6D0CC3B8322D303CE6C06365A0C26828CFD7E0EF5141909C88755DF3341CC1D04CD33FE42D48981825466A35F874E4B4A7FBEB5E4A6BB511A3A07E1360C3C9346F0DCC1EF96E50C5333B7300C010F4AED82FBD6AB688BF0FCB32A039ABE69104A29637AEC7BFF7628252CA4E7F6E630DADC9FEAA712F85079DC9E120B157E24E84355CF01C0B1F55BD981120C289DC0A996ED71292C02CF57BF895A3B985E48523DEE5E8C8FD4E1E7958A871FC4DE7E0163AF5192ECF270AB8A0CB82968FE0FC705DA8FF72F1989EF7997AA2D31D5F9210CD8E1042FBFEEB6676A93B6E391B4D235B2476C20025199705070D814408F81C353AA1C1273CA7541F5172F675F148ACDC84A2B787D4B098F30C2C9E7E00EEE6A46A002465F1F036131E06C06C097B2148B57711009E7682E3D76392EDEA719

Len = 8
Msg = CC
Squeezed = 56B97029B479FF5DD15F17D12983E3B835BB0531D9B8D49B103B025CA53F991741298E961D1FAD00FC365C7761BFB278AE473980D612C1629E075A3FDBAE7F82B0F0AF54DF187F358852E19EA4347CF5CEEA676A1DCE3A47447E237FD74204F9A4B7F7C9CC7CC8B865B1D554E2F5F4A8EE17DBDDE7267894558A20972C9EB6CF5F62CE9151437718ED4AFF08FA76D803806E6CE47D229AAE839369E31888B26429E27BC3756021CB51498BCF2527D4BB04838BC1CEED9985A2A66FF8CB8C2D58B7099304E7F9622C583B093024A5FCDE2BE781474C159DF24D77D328C298F5766A8A0DBF7AE790A509CCF59E0CACD0ABF21492E0095A87ECDB55990093917AAA96D7F68B7B859B8094AEC0DDB6FB352A6CC1F007FA988ED764F5D6F21F9D8ADE9CE7ACA4DE6570DA39D9ACCEB46D2582FA4C4231DE0B736FB341041D24CFAE6C0761F43A2CF7383F38742579218AFCAB53D2E6816640DE05644D877558E965B1A28406999F31CCC43AC0B02BC5448B66AD3B6F8DE04C0E25845C8671B6F0594909A057F17FD06031707C8B4599889C994A35C193DBF84A7A0919CD054F67CEB7965F420D02DA3477EFC8B55413C241ADCF71CB10FE7E3E720B8C1736837B06E4B27461B71C6CAC892437530BBFE05CF426272F80F11709B9DB964F5DEDAB9E757C2F7A972B6A4C2443B03AD787AB1E243660BCED739157A434800696841ACEA4

Len = 34241
Msg = 0218C8A13FC33D77350FA1F41CAE4447332083233B7EC49D11668473B50E2CA18CF2F945C3F9BBFB11CB52935AF8CFCB9837C655FB04C5C3980853F888F581818EBE708C44488EE0FF0F395B5DD626BD0422BF0DD0E2A66836EE5A2AB15281FEA726A8EBFF541B9F2F3DB3677A279E106EB09C542BE2D875CE6926972136270D50AAF056CAE76629E03E21693CFA267A27B8F79365BF01BC4A5CF8EC745FBCF4532CCA719211C608E742C1D416DFBDB24E8C866800A981FA3E7FC79CACDE73F5A925763867A82CA6F7FA327F6270225A223F1D70CFA7279BB5AB5CE096AE7442BDA7019162384DD5D6F6620331D1AB25F13FCC22F9EEBCCD753186DF2F4B4F1D4D22056F2D267364713599D79CEA52DA6A438874198C7089D52761B009829939C5C9B2F46530ED16C5081E6DDED3D42DF07190D833E8B88FA8576218D2056D71DFF547B79E9890B0B19B2DABA25A4D416165F0DAAF237399A9488FB83146DF8A327728FDAB520AD845F85F3825154FB2C73A00BE5CA7133221556A87359C1EE8307E8B4EAA8D62D8242A61E1677B28D4286978AE32460F489831C058A809CA5CECC1E1F3503487935F84873C4E53E8169F6EB44FC8604B7EB98700B68EA485EEA23D48937C808A9B244AA73499482E1512BDB151513812023AFAA848BFBF0FA353AFBA3840324438CED61C99BCE722CCC5E8A439B3FAD42A2DCF9A27D109ED3D13CA3225F3EBD6E85EDAA217B31D42E577B639373685A156350C521C41B87AB53A42B33E324A742EA3D33A3950ECC21DE6727B225DFC9321A95FCD950772DBE0CFBAFF1C623888B39AF0E8E5CD38FFE025F8B02852D91A231005329E6D4435F0413EC4E0E44C371322D92D4D510DA1163210EFCBB7DF2C2E16ADE71B75EA912264C393257BFB05CD6820AB11A2BE7B18476395B5C1E6422D7DD8ADA4F5C61FF2C99E95DF1D54B5E9933291DF5DC099DB54813932913BE2D092BD75CFF36579CE31C1393B9F018EA5E95C0C163FD40F755B185C2FA0BE15DCE5D643C2CED0714D15E21509A47E07D1E4374DE80DEA0BD111D7441B4377652518296C2283CC4056D157E4D4DAE148539E270D9140EE1F69ED7B8A145536EF1ED0C667B3D01C4468DA7CF0EBB5F4AF4771C4304CD56414D597E64C71C36E6325C1C35F6DC0DF4737F5FFFC8FCD47C8B06103E548459097D00E23CDBAE10975E90B93C5B1221D4AE221E4DD828B05949177547C593B0F2E964E201EA64B9DBC858EB45F2A0BCB168639C04D4A916241F6F88728E1013BC44E95A9FAD410642C15ADCE0D7D7528D691EA3771CFC07E25ECC1DEE69F86943264DEA0EC40BAE54E31C4E78A8EC0F6CD4EF6147714E7DCBB719C027873754185F93733F2661FB926B31B48DF68D505B7254094343EF443A162CD7223026D7EF5102CC5377E07462A2DADA527D0A5F0AB51BFCD6AB38B17C468101A151E948F2084F307C4B2F1A5A0F502B44311288714E22DD1DFF6C99E44961D28EB5EBE834CDDD4156357AE4C42E104DAC302F2DFC77F1D3C29B31938473677D67D93B8E3428ACBD8A758C46FCC882A3686BFC01FB550A8E8ADFA5E3DB9904F90A6D06E29EA7B4E6D3816CD3EB8C837659DB5DA3B282FB24917072B010066C0D3D614EDD3DA4BDED9169074491B659C6C60E621B8C7D88DFA9A7B4F0F5FF3DBD08DEA259E9C511B223A1C4F4A835F32C124EB52726394A40667798EB2B5796EE8A10D55E2518EA0F75B3E2E334405B4BB69A7BA9FAABFABB546822BB16D4D2428FAFA1B7108FC51A1D073A0E1034234A2C4CD56D60FC63884D92C35BB72E1304D31DF91D5391CC0CE2A44FCFAEF7939A418ED093112C1B94FB63D32FDD1C42BB03CEC21F9899B598BF82BDF0DC7185A2683EC7D00EB2B28BB9C63E43921339A7F5A27590DDBAED92679DBE76D530941549BF9E7898B5290268900FF925E72D511969CF1BBEB1D3421FDB695AFBC17C3DEC4C6962E7F0B7FC37F52E6BCBC5307C8EBB115F562FFD64BD4667312948F349A8405720ACB5696D1C76B288A032085C914B95C5C911A36B228004E3A8234FE5CFB049A733060B92C82950C335715AC4AB7FCB0364E53393D77D61F88798F54964EBF1A81D813EA5B3FE98BE0910B66FA2A5010411A804B6B191A3C3098A94F2969C8C166C3363E6A1A694D0B3ED415518297E41C219F3F2793F9BDA1B9A969EE964AE3F3B9E08D7FA23291E38CBEB33E450C8B9EFDBB6404486F1ED8861D4D98D3C7EAABFEA4DE115530D87BC79224034E1345AB2D23805B069CDF38E2949234E5817F34B88ED660E243ED74FB63518B402B100620A8ECF8CD64F68C9C0A36F8508416F36452C39E4E319540DF77869497182009EE6571DBE1FB3C2619F538D390904B3CC7E5B0A76AE8173FF18DD9C9FC0C2DA98DBC00640C18EEC24DEA6BDED3C6D15E2C0C1AB896B0149E51DCC58780624889C0BDBA60285252959C28BBC72C6D814EDD7A0FFD4B6FC717A5A93E3C2FA520EB59AB0673E4F13689DC8D5C992002231D0E0093AF90BAF3ED7652FC1C65CFF93C704F9F4AC99078E0CF48E107413E8E6CFD255539CE8A74FC7435D96456C1A9D81DC447D7DC52BAE2AAB22C6E2E747DB6F97CF5C6983F6E0A081F1584F6B9E7DAB37647348D6D9F33A1F88FD96ACE0451112F87230E824B30D62C13A2DDA884234E2537E7A387A7D221B98726FB41EEB22681BDDE2D6A620A3F61705C012FC8B0B504835AA4C5E801D4CB3C3891CBA52D797159372BD3285109B8547145829EFAED820230AD6154163340C275A0BA03834F91614EAFC780940939FF04DBAFC14797A676D01C1E1E67AE6BF3B0F9A40E1135C35F14308E23A239083C8D955FB6F4B17FE615416F7A58E50BFAA3E673AB7D01337F34BC5C758504410F137FF2A9BC0C4A56EB5089A3DC07DA3CD45B4B6FCF9CE73242C4E9CDEE152B33EDE9E3C3C24E4323628C351C793D523E03B59F2ED097C467147CA96892956721D05A5072C24555C4647AA1E5B107425E8399AD8F82E2B83C8CD0CFAF31F6E569103D6BA26073A2FEC572A6BBA61FE51F947928D93A7E9D71BF0CA75FBE48A1D4B13CD5E3BEB2A037FFA8DB9467828F19C9E8B8AEB8EA0BC714400E8B467372929FEA5D27145A115151BD678EB65C555CA90EEE71C6EAA0FC880AEACD10D0373B60D81D83235A260CEDF372088C9CD750075ABD3D093C257FFCC91BE0F59AF1B25579C723832AA7D20B5B971E9AD5A1F6B86D6679B8F89DE92AE04C44B184FA33EBE931D1F452015BE877CF17F3524E071993D3F0691543EED5BBDC2CD1DCB4D41456A01D0C027CCEC03A8B344DADBEFD751A8FCEA43976F28046844D1398969D161DB98953CED51EEF36BE38B8E11D028FF1ECE7BF506C8945995A66B44BB5AC0C1180BBC73FD5C8F0CECCB12F339E1BE47099D8E863AC8F5C6226381E8132696C5D2128A8FB628A9BD7C499460DB709B492EBDCB854EB8D607E217BACB99F5CA9AD451B22C96459D24F6B8B84E542E71CA9A560C5C4FA60E1370321DB82A684B38BFF2536D8A6664820C1374FE732745C7CC640D2E679D63CFB5DF588C600D3FFEA163A459F66C06890F27BD2806BE2050BB28FC66510F1131768B651C97DA05C99B666F260FCD051951FF980C60B2AF2B49AA6F2E4801DA99FD62F43A32EBAAC80F83FFEFCE89F8A20B9AF7ACD208C1F348160863009D62BFDF448060551226BEAE201786552A438668810A307FE8778001FE56414D42B061F53FCA98924380E098CDBBDC946B80AA5343D06CF32C0B42029A5E3658098E7CE33AD1B02383501456BF154AD6AA1302819ADCF61960513D9C2DE14EE189158A28065A022AA34677B1AE96D3CDFCD8EAA788CA21B6708D783EC40029EB142BF55B818675475E5E2074FF6E4C87C5482EC9375B21E8A09F5D914A231500DC9136821E0406AB920B39813724709232CDCF1B206C6F2CBCB7A4FCE79B203E6966F599753EFD28B76B18EAC7EC596DE2B69248315E11E0D40FA0F44B94D6998B4D02CF100BEE2573716774319AA9A37075CE14BB2EE560BC6A42EE8B9D574CD2B422FECFC6D90A8BA734B000835F05FEB347A14D1116817EF0495C6658C70200470DCED1C88A4A465594F72616AB7DE8FF138CD5C90B971170D602A047F76FD4C8B4E3E3A21EA47C5AD80B6F1627EE2420A72336126206335A8D5F57D916863096BA22FB39D002EDE31C822C8E4E7C89B9CE3748D8ED035F179ADA25C96FAF953B88D3C16810138AA7831881BF9C4E13D6FACB913028C6C492010014DAF31C954BF38915C13489F80E9744F869D06785D70D48D48EC8A1864DF4D7F96CD6221049279A753D14C8C8E9DD87E285223107A61B32B9148F4EA4625CCD5BA4AF44D887B957B8F22AA963C07F61F73EAF79014827B3D59DC4EB8CB3EB98AA3F8062C294D09056C5BB865ACB72D00D17C08988406A08239E404FBDBF3391185BC62DAE0B412C64AFDAF61272FFD02CBB6876B4F1434837EB534EF9EAE3E253D2F97C51377F7EE19F5CF4A2A94BEE2E36E16A94EE7701966ACDEC78BFF46C0EDC33D591771EC46194AAEFA17648B103EE11C9E2DA78FCD8991DB954748E7309BE7B29BE74B386C48DC57D99B66C821B26AD2E6D895C69706A790BFC16F659174104AB05E5F739EEB8F251ED08F654DBC93A43AB44E17510CEA5CAED3CA694CF8C365D5821A4CB849D53094C254D47BFF7732AF4E73809FF417CA82BABE70694234C90E1B7F49C85D0745E00F4C132BBA2A2AF846BF81FD40CC206BB79DFD4C16FC3315F6E963FD064B29D63320F46601383ED74750A6FA0649B5925F89BFF68555E3067FB758DCBE0F3DEB6DF96125E558462FA86DAB016086130B3DA154EBAF6B60C44FAF2D527E47F70FBEF4485567B8477A8A496726B6871ED092ED826955E57E60658518B3AE11BCCFBAA448C8932A45052CCA5A97E4112470CE8C4F258AA7EDA990AE6BFD3C931DA2F3F4D7389EDD38DBDB48FE6A15344C095C7816BBF8DB4FCC0F6CCDD8A86AF7F44716B99BF630587A33964CF72105506B7D323142C8C7E406B4BFB15CC7E561E44313C7E499B0086FFAAE780A1E5CEF759B887ACC6254B22DBB7C56DCADD44CC1730AA817356D359CA5FA1B64D9655F71A7FB4A1C024E37E047EB22FC1E46568F95E349B88DF087808E98BA01E2307A29CA09E0598C277F05DE3FE50A3E06BAC9E1D72591337216FF8350BE8638F773152274F7494AAA01CAA394D2B744CA89EB5E2DCC118A0F5754189E8B8C58DF4F73792955D5D002F8CB3B486E445F514300A0A0999F851188688B5AF45222EDFBD029AC112830B319DF2DD9FC0CF2F3B10B3094B8AD4C8F805090DA58AFD6D2E11A0D0F271E5DD98645DFD979E9A1FDC21D7FDC6BEE67D06A95486748A30C380C293967188D83541A01922D8DA22C189B552F9DCC7789DFAEC0B9B10CEC6996198FA0974206EBE65AC6446AB52418DE343B2B407574F4216C9D4066A3C1F113A8D53A3CCDC60D41E6D85B97C05C5820FF50E68E6340D2C4DAB42827D38182BA3B59B7185B7CF70DC6036B1141F020B61D2636B4555C4ACF7BA83FA8F05AC67798C64695E6F17EB6D018128946A323C97643657D786F3E952B5436D423EC082E55B6473E07391E39FEC92B6A707167ED549162B236C2A75BD2F8107E3C4C1CF6D2AAFE5ADD18D30D00EDD378F5DD1D3786134F160D4464A68BEE5DEA916C7C94FF493595B3A8EB0093EA3A4A79D90BBBDB3B659D073969438DC2DB0DF5C914230ABFA379A17174B2109E5980AF58D4CC0D36A8CE550C76941CABEC664F233318E5F595DB4B20465665E8B0822F5F8FC8F24F9551A9BA4CDF657552A73771ED57C0CF88C2FCF5EB00E1036CBA60D7987B51E7C10F6376ACE3B478F4EECA2610CDA52C8FF1CD117225F417F78008AC4BB57C8DAABEBE0BAD24E73616A0B939F4A834A707090F2777FA19C83542603C2B437AFD41322AE68E0F18EF5C3ED93472178842B90D8CED5474FF6C984B9F84EBE5BAAB29CC79C670CC94F20C0EDCCA6268FCF680
Squeezed = AF89746B8ABB9CA58F1440BAB1EE90603D039C3C37453F4E04FE0BF40E0E24D8B6DD39111FCACE7886046067C05FD96DA0D5D5B815ACFAFDB1742EAA02986EF30FE568AB6B8550971B83A232AF68DE998A0E300047AD09C55BBC06FB241E8B5B74BF333378ACB9D14C4B3276AFC0DD935A18B1F7C1C8B0C4D5EA10EF1AE38C250D2D4A144A805FFA45189B3CF9721AAAA30988FB447EDD0159FB8ED1D7970DE458F38536315FBB9DEB68DFC1150A186218F9B4502561E4A1DAD2F42D56F5087785D422B17AE16B60D9781D26DE1AA63BF407A1842A37C2C73F8E2B628CE65D63A9AEF4B17617B1AE145820FFC6FA6AAA8CB8C144B6A14EFC654130BFE94B985F3E80D4DD43698CBDB99081002E78FC2997420693979E6E7DB1D7DE3A33063F192CB4386A3C7134770B47D62816B0BF04476D4AE05C447A2B9A834CD44F1FFDC5FCBD3A0E167F930298DF756021B77FCF82B6A10C757D0A2907A76A7AF95F242DF74B7AD499BC8E14F069545FCF62F8895F3BC6142BECD289CD82D972D3D191DFBD8D80C5016FF5D016031FFA8CCE5E8D1460C9A7A7B83050CE9F1030910F6BFB83FFCEF68BF575874627DD1A34443CA4A82399F7211BBDE5175F01BFCDD05E62C2B540EA51C42317BBB144DE768F15F0DD73460E98F36038ED19166198747D8125F000847CBB68EDA86D4C837708572BF9C7018AF62B871FBDA2BE9E784DB852
