#include "she.h"
SHE_key KEY;
void bn_printfHex(BIGNUM *num)
{
    // 发现如果字符串长度超过八千多个的话，就不能全部输出了，所以得进行字符串的截取
    char *tmp = BN_bn2hex(num);
    int cut_length = 6000;
    char *tmp_part1 = (char *)malloc(sizeof(char) * cut_length + 1);
    char *tmp_part2 = (char *)malloc(sizeof(char) * cut_length + 1);
    memset(tmp_part1, 0, cut_length + 1); // 这说明置0的重要性，如果最后一个字符不是斜杠0,打印会有问题，同时上面记得加1.
    memset(tmp_part2, 0, cut_length + 1);
    int len = strlen(tmp);
    printf("长度为:%d\n", len);
    if (len > cut_length)
    {
        strncpy(tmp_part1, tmp, cut_length);
        strncpy(tmp_part2, tmp + cut_length, len - cut_length);
        // printf("第一部分:\n%s\n", tmp_part1);
        // printf("第二部分:\n%s\n", tmp_part2);
        printf("%s", tmp_part1);
        printf("%s\n", tmp_part2);
    }
    else
    {
        printf("%s\n", tmp);
    }
    free(tmp_part1);
    free(tmp_part2);
    OPENSSL_free(tmp);
}

void bn_printfDec(BIGNUM *num)
{
    char *tmp = BN_bn2dec(num);
    printf("%s\n", tmp);
    OPENSSL_free(tmp);
}
// 0失败1成功
int she_generateRandomKeys(SHE_key *key, int k0, int k1, int k2, BN_CTX *ctx)
{
    int ret = 0;
    BIGNUM *p, *q, *l, *n, *e_negative1, *negative1, *l_2, *two_big;
    char *str_p, *str_q, *str_l, *str_n;
    BN_CTX_start(ctx);

    negative1 = BN_CTX_get(ctx);
    two_big = BN_CTX_get(ctx);
    p = BN_new();
    q = BN_new();
    l = BN_new();
    n = BN_new();
    l_2 = BN_new();
    e_negative1 = BN_new();

    // // 1. Choose two large prime numbers and a random number l
    do
    {
        if (!BN_generate_prime_ex(p, k0, 0, NULL, NULL, NULL))
            goto end;
        if (!BN_generate_prime_ex(q, k0, 0, NULL, NULL, NULL))
            goto end;
        if (!BN_rand(l, k2, 0, 0))
            goto end;
    } while (BN_cmp(p, q) == 0 || BN_is_zero(l));

    if (!BN_mul(n, p, q, ctx))
        goto end;

    str_p = "D3DCCC4B17087F4B930C2214EBFEFDD469887972D879A159B257CBEA273BF25123E45696DC2A0B6C1668658751503C1F8D1BB8A0F99AD2F615E63DCA029C91DF92AB8C70C17E7C5FB17592205C9F6656CE7B475C17C11215F9803640D646C4E4A694ABD19BCBEA76471CE28446777582DA72C76F45662E41CC5D87C4BCBA16FA21702876F26C5FE5DCF133B2EE4EEB5F67D9ABBF7635EDAA7C23D904C6E8BA40CFCEB839AB950B69B24BFDEE77D047524A9612E2317DCFE2778C928DCD4BBC78DCEC3A79D1588091745C433A490A319AFECA02AE185202D995056BC9F9C6B11496E140AB22096D1538989C336EF1DD995B7F47C13F8536238C0937BA16BBDF6D";
    str_q = "C7675C15C382FFC858E08C4222A250937E1D93995E3F30330AA970EBBE4B592B84C6D19D9A832B8109A77FBE545B3A4016C961FBB2218C5FB3612E43E085A5176865DDE68C16F8ACA26787BD4D774F08713C4FF67C15360CB409DD8BE32932FD4B919CF3768EDA81286F39EE3B231E500352F8099BCD3B8DBE8FF66BAE92ECCEA0B242444E558756BB67C932815D8D0450EC0E6F06E2366268271AD6C3D41494E214F599574F0141A731E557F41BBC0E02C856EA258D325889CA28B30DB85BD780597E83967E9C7DCB43BEF3B43CD67C113946BBF9494687D1D3864BC644B821EBE6A330DECB1E4F245B1B285170FDF44BABE2F81C69A05B2F8BA6260C6CCEB3";
    str_l = "CFF6B6FE5725F5044BE137372F816E2317CF6B11E936B5715F";
    str_n = "A5062CD9ED73373A96617FCE1DDD96C2B681DC77BFF271CC638C06D72A886F6855294EB6D1022188D7226D8CD790F5CDA4F8F898336AB2652B07F968A918AAF5025375E7C244ADAC39D8E4B348CC99D8D4D15DFF005B917386379D719F4A1994F323CDA2D223388DEF5278EE33EBE749853B71D4CC755D235E165E97775D701CE55613712B704692537F33613BAB89651F0CD6F1F9DF4E4841A8293BCBDC7847DBD21E76E1B9884F1CC6D49FF56E9CED422E66AC0014A991A8233FBE7C92A7E43A6194FC1FC746C95E4990E7D1CD71CB4331D2B2BA527E319C05F0364DF1929C7B96086709B91B515B3CB0117FDE9C15343C3CDB5A582771FF1B172DAC8AAD69CC4A63DF8825F205751C90627AAFBC4A7F5B9339405884995E0E443D4752755DEC2D6664EA515D470AB603CFBD032133E364A72FF7651E8B483396BC4F325EC280ADC207FB5FCB98AEFBD22F8E0AD9E75057A931B867B9A51AC999E98EAE38045902B174FC02A3FE9566C7ABBB168285092E7F86C97119498E7A79939DDA7395320F240CE79AC3347ECC2533F8C735E9A19DB06461A568CA0C5D9C5E78567FE0EC240CEE14C00AF0E32C1FAC8302DE681E11E2315D26933E843E8A4FE8946720206C33005246CF97334B701B121FF74810615E75B29891521E3CE2FA757FDE7EC7745E0A8285ABCDC701EE4A7A2AE647431A30BC5D1E4A2E16CEF3527122EF37";

    BN_hex2bn(&p, str_p);
    BN_hex2bn(&q, str_q);
    BN_hex2bn(&l, str_l);
    BN_hex2bn(&n, str_n);

    BN_set_word(two_big, 2);
    if (!BN_div(l_2, NULL, l, two_big, ctx))
        goto end;

    key->p = p;
    key->q = q;
    key->l = l;
    key->n = n;
    key->l_2 = l_2;

    printf("p,q,l,n,en_neg1\n");
    printf("p:\n");
    bn_printfHex(p);
    printf("q:\n");
    bn_printfHex(q);
    printf("l:\n");
    bn_printfHex(l);
    printf("n:\n");
    bn_printfHex(n);

    BN_hex2bn(&negative1, "-1");
    if (!she_encryptBignumRaw(e_negative1, negative1, key, ctx))
        goto end;
    key->e_negative1 = e_negative1;

    printf("en_neg1:\n");
    bn_printfHex(e_negative1);
    ret = 1;
end:
    if (!ret)
    {
        printf("error\n");
    }
    BN_CTX_end(ctx);
    return ret;
}

// 0失败1成功
int she_encryptBignumRaw2(BIGNUM *c, const BIGNUM *m, const SHE_key *key, BN_CTX *ctx)
{
    int ret = 0;
    BN_CTX_start(ctx);

    BIGNUM *r = BN_CTX_get(ctx);
    BIGNUM *r_ = BN_CTX_get(ctx);
    // BIGNUM *n = BN_CTX_get(ctx);
    BIGNUM *tmp1 = BN_CTX_get(ctx);
    BIGNUM *tmp2 = BN_CTX_get(ctx);

    do
    {
        if (!BN_rand(r, R_BITS, 0, 0))
            goto end;
    } while (BN_is_zero(r));

    do
    {
        if (!BN_rand(r_, Q_BITS, 0, 0))
            goto end;
    } while (BN_is_zero(r_));

    // if (!BN_mul(n, key->p, key->q, ctx))
    //     goto end;
    if (!BN_mul(tmp1, r, key->l, ctx))
        goto end;
    if (!BN_add(tmp1, tmp1, m)) // rl+m不可能比n大
        goto end;
    if (!BN_mod_mul(tmp2, r_, key->p, key->n, ctx))
        goto end;
    if (!BN_add_word(tmp2, 1))
        goto end;
    if (!BN_mod_mul(c, tmp1, tmp2, key->n, ctx))
        goto end;

    ret = 1;
end:
    if (!ret)
    {
        printf("error\n");
    }
    BN_CTX_end(ctx);
    return ret;
}

// 0失败1成功
int she_generateRandomKeys2(SHE_key *key, int k_l, int k_p, int k_q, BN_CTX *ctx)
{
    int ret = 0;
    int i;
    // int increment = 100;
    int increment = k_p;
    BIGNUM *p, *q, *l, *n, *e_negative1, *negative1, *l_2, *two_big, *tmp, *bzero, *bone, *cipher_zero, *cipher_one;
    char *str_p, *str_q, *str_l, *str_n;
    BN_CTX_start(ctx);

    negative1 = BN_CTX_get(ctx);
    bzero = BN_CTX_get(ctx);
    bone = BN_CTX_get(ctx);
    two_big = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    p = BN_new();
    q = BN_new();
    l = BN_new();
    n = BN_new();
    l_2 = BN_new();
    e_negative1 = BN_new();
    cipher_zero = BN_new();
    cipher_one = BN_new();
    BN_zero(bzero);
    BN_one(bone);

    BN_one(q);
    // 1. Choose two large prime numbers and a random number l
    do
    {
        if (!BN_generate_prime_ex(p, k_p, 0, NULL, NULL, NULL))
            goto end;
        // 生成q
        if (k_q == 33976)
        {
            char *str_q = "F18CBFC7C68A8A88B31EC3493BDEC1F1BE182E914E95E731C5BF93DCC6905D34F091D5E0F2AFE2F9BAF547E6BFCFD16F0ED64B3CB106BA9E979A0972CC1AB93B110D5D7CE7EEBD0E80EF78480B4F3869F1950ADCC6D98C16F88D3B25BD76753205CB7FACDAFF33C289D0E85BEF73AFCD17C68967B589D81DE784C8AAD455B01EB1C9DFEC4AF0287F96B7F3A7CC4CF7DF1425290288EC07762862E72499657D90FBDF4BC61402666D35E3A75DAF65AAEB09BFD81F6521D84A171885E135E5CF0D51F9C45D65E3A9C7AC87F77E9D8AB149974314ABCE3F2ED310270AB774BD64A6385BF2FA2F338B337A4FC6BBA6565511641E17A7BC48C5830213EB73A9288AF65C243B89004ADF734A7E9AEED992AA415F08E402781FD0FF4EE4F730030A790ED4F090E69842798535A3092184932CD86765B06AD305D6FB1B4B008E34D74D80A7BA34C52A9238C889528D647301652A08FC529661207D73322BAEA1F3ADE49AFB4D529EFCD606E009D7B9EF2532B629C578CA90EEA185FD6BAED3E0A823836580517E4BF1BD1B6449E5823EDFEAB3C806B91A72C6FFB68DE2C5BDF88FF9F676A2ECB73D7234DB427E7B12165FC4267CE6257E658C4A61E85A9937C5EB50027462659F0815C696F276BB856CC0EC8BA77C6E6284D463B1359AA7D9634A06A7815551CA83D600D4F5210A9FDBE5BA083309DA1E9EC3B37482BC2780F73D47A629F387C6AB5F4D3A30BB19CCCC882BBD08F4763A5B53954EDB3B3B37E30E01CFD2948086DDEF4530D11A21DDDB768C2ADB7AC6235AF92CF9231926437C97AD90801C7528A8800FCC41C1DC678E7A6BDD1A75C8F4F3374ACAD6E5CB65D51AE5C243C18D5FEDB5BAA2E4F7CBEF32A49D7603C82F43B381A57C884476891DF67982F83EC22BCC314E898860F7156AE72BC984D1E47CDA986BF7BDE8912F898D4EF0FCE02FF8CB663D03C4393D0BEBAF3A91DD5F9E0509B2607EF62A8887FEB3B3E4CFAEDE4D7793FB8A5C07A99808DC76E293154734B1D8BFE070BEADD8B3C4851FB8E0A9D03054936D7AAD3A82365960A3A9AABC08159E20A5C6F9ED38A400749D1F0F9E9AC2FD7BD63AF8DDE693392E88528BE5574A682C0A0E7780817FE058226CB191C504A08906FFD846728C4A226E71088269B15F6023320C6969E43565A5D8B832D089C7DD8E600091C5AF761BBF17A88C14EF9C1B8F69E5833294950FD64FEB42BA5473996464FECDE9235A360B643335C14B7582D80637A3CBCC51BA36BEB0CF93917AC8C073F2955E3866793819F5246B4AF7E2D95186FE608F9F4F3B6DC9C7965AB06CFB45A795C159D2F992449DC7ED9212C4595D772C76D6A16EAAF7E94D97BF3FA251D24002E9AC2C55D49FF7F149E5A4AB967A467D439C958A301C4FDCDA6EE908DCA6D6898C491AFC0623C3D9E7BC35DD1564DF658D7642D435E5EE827ED4BE0A2FD4AAE941AB90B3DFCE7945534E180CB54DFE0CDD8F30D2A0F6AA5C8DA9290CD9370F0EFF52CE895B04E5A01084A087FC6150269BA9B6EBE293E366E3BBD92C02C3B92A644F7341D383A2EF9BAADC15FAFD8985D9EEBEA9711434092296EE9BB91B3E2A7D227EAE558E2E4CA229CE8712E49522F9EC50B9A24128BAACAF8F5EB6D8491B2FE2CD42824C2546D504CC4BCD02C51FE02F58540F4074D868FEBA5CC39A0281215779F99F4084639C1D1DFB681BFCC6D75AA45064A5A01C7DC053BF22997674E2651972C2312AD4C99F4531370E48B9E861B8D8DFE144ACB91DECABFCB6D66A2AD5A4EE045EB1097DC14A5002324A4B82EA0A7A84727001A7ACFFA5A9213A31984A078F4CF7347612BD344516469573A97B35435F50B728BEE56D873C61D2ED471DBC0A5515B9F983923E02A8AE76DAED9C5AE07CFE0A0452784E10F1D23294FBAA8B1B6A811B15355A338C30A5316FEEBF8615C327ADDC9E6C3DA6891D678FCB15D52C2087582F51ECD368DE1E5B9EA2370A5E59C03BC12B98E4195C4322A3B69BFDBD36D487B0C797CB89FB7E1C6DDBD72C3F56C1D1BE6913AD10173CC7AA611B734F3AF4D1E68C30C1B5505D337A284507E86DC83DFB6CAB716F67F03403366F21C4BB09137E9E9D050F07A4774C32973768611406203ECAB9FBBD05656A265E8C8A42DB659B4D12632AFF2579E3562D9B9BAEF272AB0B6BAF9A986D616C69E97F5078070BF532764F6DAB32D94A84073498A95A30B6C24429A49CD4586C3A86D7FF85F87CC4563FA2755BD166F3DCD26D1EBEE7B2BE8B6CB960F4FC861FCF4A1036100DB4902151807608A404A983945F77D03D0B86864C59269D825356910F8F497A0A5C486443D6A52E8F1A56F38D286AD0CB9F72F600072CD731DF4F9FA6F51E026665AAB5735403C97B30DF750146A6FFF0CE029427BC40527DB76727B1C0C977CAB06EA43941F9F1E2BC03CD6B5C053A0070D944F6344EBD235E60BB0271CE8AFF5E95E6A6FC33D287431BA0BBD109FFD2D033F70014E68A421D8CD961D0385DE173DC960353792EE54AAC389D638B42E47E472372DE2495929746EED7197D713DBF82BD3A04AB3115EE75240AB842B0C1FAC6153356FB86A140C72DC20D98F5C4939482BE1A1222549BCB26BA54DD42544A572E88F6CB841455BCCC774EFF8BB76C58CC2D550B4A9F5E47F0727F019ABDAD980262173559FF018FD8029D6E7A2F146E9D8EBB02CF10F9583C0718D9F5BFC73C8F356462C906688F96B2435966814E792165350E60D130C64F50D15158CB1CD058C600408E67093BB580B9AA18B945A71FB17173728791AC47B47E2FA621A15DF05F69C96C8B72C81700AF67FCE4A0D15FF1361306A68FA624DD63C111042A4C595D109E3D6F2BD2E37C82B5953F4D444C9CB133C8D0AF6E2542382986CB74A6EBB6A1CBDBD95C5CCBADAD1B2DFE84DFF763FD8A9A872CACED8F78B35D7CB3146BA3AF940618C9AE70DFDEC579F6368DD9A3A9828B63AACBF1289A1BAC4BB6E98F9CB6325FBBCD1B73E6C598F2491509F9C41CB9D92CA3B9EDFD8F7E2314CA46A9C4C60D7344AFDA20DE50B8869AFEA8798D0FCD9BA87D9702FB612FB63892BB4EF8243E6C0246781911F7A4D9FF91463A677A57E65EA11AB318A1BB7682AF453B9AC425AE4C77671E34907F558A492821BCC10A9069EF53CD8B47007F0A77C6C1680B12A4936B7FEDB51DFA526BD54FF6FF13165E685457F4C582BC34D6925D1706CB5B2221B9538095A169D772332C55CE928E6FE536702C2D980E1A15C9839CE8876392F0CA2CC893AEC94366E4381E538BDAC1139DE23321D6B7D1733D2A5FB2DA192E0BA99C0A3BA94673ECDFB19DFDE6F5D60493C10EB1BB3D03C9A5C1DEC21A4EDD8E2C3F2C1AF9F12E35E34DCFE5B26C143108F5534A410E3391EEF81A8B9656BA76072C382EC18B456BA72DA6476783D7B30B996C87FFB7100E3ABE0293F1FE819F9DD5CA98B338DABD87FBB00E74CFA68997D9A9D8FC5CB88159BCAC2AD52BAFB153C2DD56ABD98D905CFD5FAB1E5759E95EAAE9E11BC4EC3121F6883CA357B044E9463105CB87D7F5D69DCD7AE588B61CBDF1C5657168DCC01A9EDC736EBA9B022A343DF069C68A634B59D9C10337BD4E7B6752CA0EDBD1A4A631E73EF8D9D905583DD85060141963230CB9CE20F2E86D8EFB094CFAAB6F14400EB1C9E03EEE4E80186769AAC00F05700834E00292BD614F356AD8482643A7171C451F80EA2D4706D1DDB19775011C953C33D9CBD9F40373E2BBCBE833B5A19531F68EC993D299C6BD6491D62EEBDFE8DF935D961A0476B3DEABA9F2F1E6DFBDCB71CCD010D180719B7AC32E69958EDE6EC31273E04D5C23D8D130603A2D4CD08E532575BAAF49FDC1C16121A8183BF5A004641CA86EA9A5B9F39556C9B4073F25E8C87695A496FEC53ABBE91EA34CE30DCDF67984E114EAFB0246A4A57465954E5537B7CB6A05295963178A9EDEA798AFE2641EE14DE0602C69D46361AE627EA196D0393F12C92DDC8C613654B76BF71170F74C7947D182B8A4F46A6C5D27B7371BE9980942C16E2554FA43559EAA6C5B3F402CF94233C51A83335CABC6F9379FCA69E6136CBCC36F25BB3FA4DCBBCE2A2AD96349B55CE06437B486FB564C49CD4D8248A4FA15D48997DEF4EE0E5FA608450BD2209FEA21210DD46846946968EC564BCEEC5C0EA4FF50EDB014F31D582D36C9151CDB347FD903F2804D54C0FCDEC063E635FA74596C0C3408C61E693E6A6EF3CA923329798B9DAC0C20A4684AD4A11AAF0F5934C2985001747C27AA72C63A8A65F677A4CA9115C13BEF8587E147D12FB5C35003B0C99DFA585CFFB8769B73C81F805F33FAB299932B6EF8EE09E388DAD61073717B835EB705DA0D4B7F8666306893CC40A9442E96579BF8D4857B0B8AFD0385ECEA930F7387EF07296366576B4A51B7E8F0C2E6122815B38868A79719329192347EBC2695FC7BE4BB76E6F2CAC5B2D2FDDE8DA6A776322D38D69C55F22BE9B1DCF5FB77AC55FF6B95EF2A824EE4ECECA872D457578382ECA3CFE6A28057736D4D64A515D1C9BCA2ADB63DBFF12990C1BDC5905342D26EC98690FD5A92748F956F7AE5C1078660CCE105A32B3707C49C0725F9C420F645B366685A9C05808C8C7CC1BA2C0E6303F85A229C65BAFDABAE1EB68187DC1E8219905C0FD3FEF2899E9EB38DE599C458E5E8BCC8052FB654582C27C0D7B9DE57E5CC84BE4E81BA7C6AF303214807884C3C539274660BF832DE0433BAEF2D93DD589EB5611157316CEE7718E4A3C6E4E404092A71865EF4BAF047BBA618B0D93D60CC5E6EDAD095EE8544FBCE8B7674EE647CC7694F6BCD5AEFCCD2B26FD7EDE5F2290AFCBED14A66056E603F093E180DB85E03B2BD8D347601DE0927DCE576CF16BD2843CCFBFA9431E95D258CD2CD4D3600C52182CE0D4AB53A591532ABDB7DF8B89C9EEA7586ECBCC87FD56033A33456A03FC1680A2BD31768FD4AC844CF43A06BAF58EF3665DE9A26462660A73B625276A8A623D5E8E4482F5801068807C86BDAD1794B841B22B6AB9E4B947E61F5B788D2EE84559C242B2ECAB724D4FFD0231FD4A69B5A610688A2BC4DB423FAA707D2F1D0B37D483299752F9D61514EA32602693746398FB532C96EA516520EE8A10B5889BF95600E3C0C04377F65AE6B1DE09E2280A17977A0C40A8830E4DE5DC1E14D533175395EC69388DA39535A00BE8223264D48230A7FD8C808C12E8A85D85209FC0B4305EDC039522B5F02AB455099FD969A5498E8C602A183FC1A50B3850692206C7C277F8D887714B9A1EA313A733602F5A08CCD46227580398F84A9C9E76C0D7669B5B53FAC754B1CB4B0863CFC9E769491EB81CF8CEE3924AED1CEF2BD8BE71BE3029856439BE5716C63B7186E5D53E624766D78FDC607191FDC6D65E3CCE036C6A41044E96335AD842882F093714103B114C0D74CA6CD83D9B485215CAA6F2362F341E306256F848FBC2D5FE0A1F189791A09FB3E852A192F3530F26E649290F55A9E40CC1DE2351BC87ECDBD327C7A61CEE623B07ACD07DDE81CEE32EC8CC84DD198107B2D20AE4EB6C6A67BFF13A9BF0727B08040E561DD15FB45971762E9F51285F27E2E6D89AB994C874EE324C31FDD31511AD24FB4F3C3ADDB9BF4F0830C1956E8BA6F674B07422AD54639B7AA2C37B9E7B17119C4763501E7BFF2FACE7E8B87C2201E30493A87D6E8EB88301E00E26EFEC40600D8490498071141DEAAF87816E94539B19B2F821BBB1FFAC7525799A40EA03EC76B4364E7A10F4816906011991B02662BCC614FD5A387B9F065FF55366453A6C67C5D3101944CC15A87884CE505C3FFA7204236C91FCE49CDEB10BFE5BB35932D5A8689DBCE28B6A1C10AD608D3173AF5F28D812FB15183864C0897CF4CE0C006423CD3CFA8A220F359B685AB68FAE453D7DAC66F362F42D6034B02DF21024A29AE2BCC21C9A5BA200294C59DBBF8A4FCF88D1E88FC95F32E82CEF07566A4BD28231E38393C6A42D72AC2F9110F";
            BN_hex2bn(&q, str_q);
        }
        else
        {
            while (BN_num_bits(q) < (k_q))
            {
                if (!BN_generate_prime_ex(tmp, increment, 0, NULL, NULL, NULL))
                    goto end;
                BN_mul(q, q, tmp, ctx);
            }
            while (BN_num_bits(q) < k_q)
            {
                if (!BN_generate_prime_ex(tmp, 100, 0, NULL, NULL, NULL)) // 最后步子迈小一点不要导致位数超太多
                    goto end;
                BN_mul(q, q, tmp, ctx);
            }
            if (BN_mod_word(q, 2) == 0)
                BN_sub_word(q, 1);
        }
        if (!BN_rand(l, k_l, 0, 0))
            goto end;
    } while (BN_is_zero(l));

    if (!BN_mul(n, p, q, ctx))
        goto end;

    BN_set_word(two_big, 2);
    if (!BN_div(l_2, NULL, l, two_big, ctx))
        goto end;

    KEY.p = p;
    KEY.q = q;
    KEY.l = l;
    KEY.n = n;
    KEY.l_2 = l_2;

    // printf("p,q,l,n,en_neg1\n");
    // printf("p:\n");
    // bn_printfHex(p);
    // printf("q:\n");
    // bn_printfHex(q);
    // printf("l:\n");
    // bn_printfHex(l);
    // printf("n:\n");
    // bn_printfHex(n); // 喵的，太长了，打印不了。。。算了，又要分割字符串么，拉倒吧，我也懒得写了

    BN_hex2bn(&negative1, "-1");
    if (!she_encryptBignumRaw2(e_negative1, negative1, &KEY, ctx))
        goto end;
    if (!she_encryptBignumRaw2(cipher_zero, bzero, &KEY, ctx))
        goto end;
    if (!she_encryptBignumRaw2(cipher_one, bone, &KEY, ctx))
        goto end;
    KEY.e_negative1 = e_negative1;
    KEY.cipher_zero = cipher_zero;
    KEY.cipher_one = cipher_one;
    // printf("e_negative1:\n");
    // bn_printfHex(e_negative1);
    ret = 1;
end:
    if (!ret)
    {
        printf("error\n");
    }
    BN_CTX_end(ctx);
    return ret;
}

// 0失败1成功
int she_encryptBignumRaw(BIGNUM *c, const BIGNUM *m, const SHE_key *key, BN_CTX *ctx)
{
    int ret = 0;
    BN_CTX_start(ctx);

    // for test only
    //  const char* rl = "A365CAD30642EA0FC8D1BFEBC0315DB0F28BAB4B67866DEFE0";
    //  const char* rl2 = "8376B295464191D488DFD3154B2B889E900E030C3C7D0CBA55D41BF155C149CCF65CC33D461E9FCE82A96921CFE3BF6B5AFB8E517BB46D83D0E6AA19D64468655F330B98D98EECEF1CCA99458FE84A9FEE1F25EE6DA5EA0456291280802E754295688FC4512A8495C9AEB0E23F02EC2EB1BD304DBFC771B5C75E660079254EB6E84F41C79BBD48F7CA83FDC37261BFF2925439E31123EE5374540B121D8C52027A703287B261F4352B659171C32B00BBAAB87678C9D9B1003422BB52BCF31C3B8D564B1A14970528E9C00B0057462BFD177931DF46F42C0B49683CA3CF44A78183E4A2A767CF5468B4AEA6899D05E5EF32CDD38FE3F6978B20F1E1DFA6CE71D4";

    BIGNUM *r = BN_CTX_get(ctx);
    BIGNUM *r_ = BN_CTX_get(ctx);
    // BIGNUM *n = BN_CTX_get(ctx);
    BIGNUM *tmp1 = BN_CTX_get(ctx);
    BIGNUM *tmp2 = BN_CTX_get(ctx);

    do
    {
        if (!BN_rand(r, DEFAULT_K2, 0, 0))
            goto end;
    } while (BN_is_zero(r));
    // BN_hex2bn(&r,rl);
    do
    {
        if (!BN_rand(r_, DEFAULT_K0, 0, 0))
            goto end;
    } while (BN_is_zero(r_));
    // BN_hex2bn(&r_,rl2);
    // if (!BN_mul(n, key->p, key->q, ctx))
    //     goto end;
    if (!BN_mul(tmp1, r, key->l, ctx))
        goto end;
    if (!BN_add(tmp1, tmp1, m)) // rl+m不可能比n大
        goto end;
    if (!BN_mod_mul(tmp2, r_, key->p, key->n, ctx))
        goto end;
    if (!BN_add_word(tmp2, 1))
        goto end;
    if (!BN_mod_mul(c, tmp1, tmp2, key->n, ctx))
        goto end;

    ret = 1;
end:
    if (!ret)
    {
        printf("error\n");
    }
    BN_CTX_end(ctx);
    return ret;
}

// add support for negative numbers.
int she_encryptBignumSupportNegative(BIGNUM *c, const BIGNUM *m, const SHE_key *key, BN_CTX *ctx)
{
    int ret = 0;
    BN_CTX_start(ctx);

    BIGNUM *m_positive = BN_CTX_get(ctx);
    int positive_flag = 1;

    if (BN_is_negative(m) == 1)
    {
        BN_copy(m_positive, m);
        BN_set_negative(m_positive, 0);
        positive_flag = 0;
    }
    else
    {
        BN_copy(m_positive, m);
    }
    if (!she_encryptBignumRaw(c, m_positive, key, ctx))
        goto end;
    if (positive_flag == 0)
    {
        if (!BN_mod_mul(c, c, key->e_negative1, key->n, ctx))
            goto end;
    }
    ret = 1;
end:
    if (!ret)
    {
        printf("error\n");
    }
    BN_CTX_end(ctx);
    return ret;
}

// add support for negative numbers.//加密你要自己保证m在明文空间里边
int she_encryptBignumSupportNegative2(BIGNUM *c, const BIGNUM *m, const SHE_key *key, BN_CTX *ctx)
{
    int ret = 0;
    BN_CTX_start(ctx);
    BIGNUM *m_ = BN_CTX_get(ctx);
    if (BN_is_negative(m) == 1)
    {
        BN_add(m_, m, key->l);
    }
    else
    {
        BN_copy(m_, m);
    }
    if (!she_encryptBignumRaw2(c, m_, key, ctx))
        goto end;
    ret = 1;
end:
    if (!ret)
    {
        printf("she_encryptBignumSupportNegative2 Error\n");
    }
    BN_CTX_end(ctx);
    return ret;
}

int she_decryptBignum(BIGNUM *plain, const BIGNUM *c, const SHE_key *key, BN_CTX *ctx)
{
    int ret = 0;
    BN_CTX_start(ctx);

    BIGNUM *tmp = BN_CTX_get(ctx);
    if (!BN_mod(tmp, c, key->p, ctx))
        goto end;
    if (!BN_mod(plain, tmp, key->l, ctx))
        goto end;
    if (BN_cmp(key->l_2, plain) == -1)
    {
        // printf("the bignum is negative\n");
        BN_sub(plain, plain, key->l);
    }
    ret = 1;
end:
    if (!ret)
    {
        printf("error\n");
    }
    BN_CTX_end(ctx);
    return ret;
}

int she_decryptBignum2(BIGNUM *plain, const BIGNUM *c, const SHE_key *key, BN_CTX *ctx)
{
    int ret = 0;
    BN_CTX_start(ctx);

    BIGNUM *tmp = BN_CTX_get(ctx);
    if (!BN_mod(tmp, c, key->p, ctx))
        goto end;
    if (!BN_mod(plain, tmp, key->l, ctx))
        goto end;
    ret = 1;
end:
    if (!ret)
    {
        printf("error\n");
    }
    BN_CTX_end(ctx);
    return ret;
}

int she_encryptTeeStringBignum(char *str_c, BIGNUM *m)
{
    int ret = 0;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    char *tmp;
    BIGNUM *c = BN_CTX_get(ctx);
    if (!she_encryptBignumSupportNegative(c, m, &KEY, ctx))
        goto end;
    tmp = BN_bn2hex(c);
    memcpy(str_c, tmp, strlen(tmp) + 1);
    OPENSSL_free(tmp);
    ret = 1;
end:
    if (!ret)
    {
        printf("encryptTeeString error\n");
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

int she_encryptTeeStringBignum2(char *str_c, BIGNUM *m)
{
    int ret = 0;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    char *tmp;
    BIGNUM *c = BN_CTX_get(ctx);
    if (!she_encryptBignumSupportNegative2(c, m, &KEY, ctx))
        goto end;
    tmp = BN_bn2hex(c);
    memcpy(str_c, tmp, strlen(tmp) + 1);
    OPENSSL_free(tmp);
    ret = 1;
end:
    if (!ret)
    {
        printf("she_encryptTeeString2 Error\n");
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

int she_generateRandomKeysTee()
{
    int ret = 0;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    if (!she_generateRandomKeys(&KEY, DEFAULT_K0, DEFAULT_K1, DEFAULT_K2, ctx))
        goto end;
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    ret = 1;
end:
    if (!ret)
    {
        printf("generateRandomKeysTee ERROR\n");
    }
    return ret;
}

int she_generateRandomKeysTee2()
{
    int ret = 0;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    if (!she_generateRandomKeys2(&KEY, L_BITS, P_BITS, Q_BITS, ctx))
        goto end;
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    ret = 1;
end:
    if (!ret)
    {
        printf("generateRandomKeysTee2 ERROR\n");
    }
    return ret;
}

int she_encryptTeeString(char *str_c, char *str_m)
{
    int ret = 0;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    char *tmp;
    BIGNUM *m = BN_CTX_get(ctx);
    BIGNUM *c = BN_CTX_get(ctx);

    BN_hex2bn(&m, str_m);
    if (!she_encryptBignumSupportNegative(c, m, &KEY, ctx))
        goto end;
    tmp = BN_bn2hex(c);
    memcpy(str_c, tmp, strlen(tmp) + 1); // 但在C里面是可以加一的，不会出错
    OPENSSL_free(tmp);
    ret = 1;
end:
    if (!ret)
    {
        printf("encryptTeeString error\n");
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

int she_decryptTeeStringBignum(char *str_plain, BIGNUM *c)
{
    // printf("shou dao miwen:%s\n",str_c);
    int ret = 0;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    char *tmp_;
    BIGNUM *plain = BN_CTX_get(ctx);
    // BIGNUM *c = BN_CTX_get(ctx);
    // BN_hex2bn(&c, str_c);
    if (!she_decryptBignum(plain, c, &KEY, ctx))
        goto end;
    // printf("解密结果为：\n");
    // bn_printfDec(plain);
    tmp_ = BN_bn2hex(plain);
    // memcpy(str_plain,tmp_,strlen(tmp_)+1);
    memcpy(str_plain, tmp_, strlen(tmp_) + 1);
    OPENSSL_free(tmp_);
    ret = 1;
end:
    if (!ret)
    {
        printf("decryptTeeStringBignum error\n");
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

int she_decryptTeeStringBignum2(char *str_plain, BIGNUM *c)
{
    // printf("shou dao miwen:%s\n",str_c);
    int ret = 0;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    char *tmp_;
    BIGNUM *plain = BN_CTX_get(ctx);
    // BIGNUM *c = BN_CTX_get(ctx);
    // BN_hex2bn(&c, str_c);
    if (!she_decryptBignum2(plain, c, &KEY, ctx))
        goto end;
    // printf("解密结果为：\n");
    // bn_printfDec(plain);
    tmp_ = BN_bn2hex(plain);
    // memcpy(str_plain,tmp_,strlen(tmp_)+1);
    memcpy(str_plain, tmp_, strlen(tmp_) + 1);
    OPENSSL_free(tmp_);
    ret = 1;
end:
    if (!ret)
    {
        printf("decryptTeeStringBignum2 error\n");
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

int she_decryptTeeString(char *str_plain, char *str_c)
{
    // printf("shou dao miwen:%s\n",str_c);
    int ret = 0;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    char *tmp_;
    BIGNUM *plain = BN_CTX_get(ctx);
    BIGNUM *c = BN_CTX_get(ctx);
    BN_hex2bn(&c, str_c);
    if (!she_decryptBignum(plain, c, &KEY, ctx))
        goto end;
    // printf("jie mi hou:\n");
    // BN_printf_she(plain);
    tmp_ = BN_bn2hex(plain);
    // memcpy(str_plain,tmp_,strlen(tmp_)+1);
    memcpy(str_plain, tmp_, strlen(tmp_) + 1);
    OPENSSL_free(tmp_);
    ret = 1;
end:
    if (!ret)
    {
        printf("decryptTeeString error\n");
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

// E(m1)+E(m2)
int she_addTest(const SHE_key *key, BN_CTX *ctx)
{
    int ret = 0;
    BN_CTX_start(ctx);

    BIGNUM *plain1 = BN_CTX_get(ctx);
    BIGNUM *plain2 = BN_CTX_get(ctx);
    BIGNUM *cipher1 = BN_CTX_get(ctx);
    BIGNUM *cipher2 = BN_CTX_get(ctx);
    BIGNUM *tmp1 = BN_CTX_get(ctx);

    // BIGNUM *tmp2 = BN_CTX_get(ctx);
    BIGNUM *res1 = BN_CTX_get(ctx);
    BIGNUM *res2 = BN_CTX_get(ctx);

    if (!she_encryptBignumSupportNegative(cipher1, plain1, key, ctx))
        goto end;
    if (!she_encryptBignumSupportNegative(cipher2, plain2, key, ctx))
        goto end;
    if (!BN_mod_add(tmp1, cipher1, cipher2, key->n, ctx))
        goto end;
    if (!she_decryptBignum(res1, tmp1, key, ctx))
        goto end;
    if (!BN_mod_add(res2, plain1, plain2, key->n, ctx))
        goto end;
    if (BN_cmp(res1, res2) == 0)
    {
        printf("同态性质加法验证通过\n");
    }
    else
    {
        printf("同态性质加法验证不通过\n");
    }
    ret = 1;
end:
    if (!ret)
    {
        printf("she_addTest Error\n");
    }
    BN_CTX_end(ctx);
    return ret;
}

// E(m1)+E(m2)
int she_mulTest(const SHE_key *key, BN_CTX *ctx)
{
    int ret = 0;
    BN_CTX_start(ctx);

    BIGNUM *plain1 = BN_CTX_get(ctx);
    BIGNUM *plain2 = BN_CTX_get(ctx);
    BIGNUM *cipher1 = BN_CTX_get(ctx);
    BIGNUM *cipher2 = BN_CTX_get(ctx);
    BIGNUM *tmp1 = BN_CTX_get(ctx);
    // BIGNUM *tmp2 = BN_CTX_get(ctx);
    BIGNUM *res1 = BN_CTX_get(ctx);
    BIGNUM *res2 = BN_CTX_get(ctx);

    if (!she_encryptBignumSupportNegative(cipher1, plain1, key, ctx))
        goto end;
    if (!she_encryptBignumSupportNegative(cipher2, plain2, key, ctx))
        goto end;
    if (!BN_mod_mul(tmp1, cipher1, cipher2, key->n, ctx))
        goto end;
    if (!she_decryptBignum(res1, tmp1, key, ctx))
        goto end;
    if (!BN_mod_mul(res2, plain1, plain2, key->n, ctx))
        goto end;
    if (BN_cmp(res1, res2) == 0)
    {
        printf("同态性乘法验证通过\n");
    }
    else
    {
        printf("同态性质乘法验证不通过\n");
    }
    ret = 1;
end:
    if (!ret)
    {
        printf("she_mulTest Error\n");
    }
    BN_CTX_end(ctx);
    return ret;
}

int addString(char *str1, char *str2, char *str3)
{
    int ret = 0;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *cipher1 = BN_CTX_get(ctx);
    BIGNUM *cipher2 = BN_CTX_get(ctx);
    BIGNUM *res = BN_CTX_get(ctx);

    BN_hex2bn(&cipher1, str1);
    BN_hex2bn(&cipher2, str2);
    BN_mod_add(res, cipher1, cipher2, KEY.n, ctx);
    char *tmp_ = BN_bn2hex(res);
    memcpy(str3, tmp_, strlen(tmp_) + 1);
    OPENSSL_free(tmp_);
    ret = 1;
end:
    if (!ret)
    {
        printf("error\n");
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

int mulString(char *str1, char *str2, char *str3)
{
    int ret = 0;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *cipher1 = BN_CTX_get(ctx);
    BIGNUM *cipher2 = BN_CTX_get(ctx);
    BIGNUM *res = BN_CTX_get(ctx);

    BN_hex2bn(&cipher1, str1);
    BN_hex2bn(&cipher2, str2);
    BN_mod_mul(res, cipher1, cipher2, KEY.n, ctx);
    char *tmp_ = BN_bn2hex(res);
    memcpy(str3, tmp_, strlen(tmp_) + 1);
    OPENSSL_free(tmp_);
    ret = 1;
end:
    if (!ret)
    {
        printf("error\n");
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}
