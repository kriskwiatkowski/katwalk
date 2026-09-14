use super::Subprocess;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct VectorSet {
    #[serde(rename = "vsId")]
    vs_id: u64,
    algorithm: String,
    revision: String,
    mode: Mode,
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Mode {
    KeyGen,
    EncapDecap,
}

#[derive(Debug, Deserialize)]
struct TestGroup {
    #[serde(rename = "tgId")]
    tg_id: u64,
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    function: Option<Function>,
    tests: Vec<TestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Function {
    Encapsulation,
    Decapsulation,
    EncapsulationKeyCheck,
    DecapsulationKeyCheck,
}

#[derive(Debug, Deserialize)]
struct TestCase {
    #[serde(rename = "tcId")]
    tc_id: u64,
    z: Option<String>,
    d: Option<String>,
    ek: Option<String>,
    dk: Option<String>,
    m: Option<String>,
    c: Option<String>,
}

#[derive(Serialize)]
struct Response {
    #[serde(rename = "vsId")]
    vs_id: u64,
    algorithm: String,
    revision: String,
    #[serde(rename = "testGroups")]
    test_groups: Vec<ResponseGroup>,
}

#[derive(Serialize)]
struct ResponseGroup {
    #[serde(rename = "tgId")]
    tg_id: u64,
    tests: Vec<ResponseTest>,
}

#[derive(Serialize)]
struct ResponseTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ek: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    c: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    k: Option<String>,
    #[serde(rename = "testPassed", skip_serializing_if = "Option::is_none")]
    test_passed: Option<bool>,
}

fn decode_hex(value: Option<&str>, field: &str) -> Result<Vec<u8>> {
    hex::decode(value.with_context(|| format!("Missing {field}"))?)
        .with_context(|| format!("Invalid hex in {field}"))
}

fn one_result<'a>(results: &'a [Vec<u8>], command: &str) -> Result<&'a [u8]> {
    if results.len() != 1 {
        anyhow::bail!(
            "{command} returned {} results; expected exactly one",
            results.len()
        );
    }
    Ok(&results[0])
}

fn two_results<'a>(results: &'a [Vec<u8>], command: &str) -> Result<(&'a [u8], &'a [u8])> {
    if results.len() != 2 {
        anyhow::bail!(
            "{command} returned {} results; expected exactly two",
            results.len()
        );
    }
    Ok((&results[0], &results[1]))
}

fn check_passed(result: &[u8]) -> Result<bool> {
    match result {
        [0x00] => Ok(false),
        [0x01] => Ok(true),
        _ => anyhow::bail!("Unexpected result from key check: {:?}", result),
    }
}

pub fn process_mlkem(subprocess: &mut Subprocess, vector_set: &Value) -> Result<Value> {
    let vector_set: VectorSet =
        serde_json::from_value(vector_set.clone()).context("Invalid ML-KEM vector set")?;
    let mut response_groups = Vec::with_capacity(vector_set.test_groups.len());
    for group in &vector_set.test_groups {
        let mut response_tests = Vec::with_capacity(group.tests.len());
        for test in &group.tests {
            let response_test = match vector_set.mode {
                Mode::KeyGen => {
                    let z = decode_hex(test.z.as_deref(), "z")?;
                    let d = decode_hex(test.d.as_deref(), "d")?;
                    let mut seed = z;
                    seed.extend(d);
                    let results = subprocess
                        .transact("ML-KEM/keyGen", &[group.parameter_set.as_bytes(), &seed])?;
                    if subprocess.check_unsupported(
                        &results,
                        &format!("ML-KEM/keyGen for parameterSet={}", group.parameter_set),
                    ) {
                        continue;
                    }
                    let (ek, dk) = two_results(&results, "ML-KEM/keyGen")?;
                    ResponseTest {
                        tc_id: test.tc_id,
                        ek: Some(hex::encode(ek)),
                        dk: Some(hex::encode(dk)),
                        c: None,
                        k: None,
                        test_passed: None,
                    }
                }
                Mode::EncapDecap => {
                    let function = group.function.as_ref().context("Missing function")?;
                    match function {
                        Function::Encapsulation => {
                            let ek = decode_hex(test.ek.as_deref(), "ek")?;
                            let m = decode_hex(test.m.as_deref(), "m")?;
                            let results = subprocess.transact(
                                "ML-KEM/encaps",
                                &[group.parameter_set.as_bytes(), &ek, &m],
                            )?;
                            if subprocess.check_unsupported(
                                &results,
                                &format!("ML-KEM/encaps for parameterSet={}", group.parameter_set),
                            ) {
                                continue;
                            }
                            let (c, k) = two_results(&results, "ML-KEM/encaps")?;
                            ResponseTest {
                                tc_id: test.tc_id,
                                ek: None,
                                dk: None,
                                c: Some(hex::encode(c)),
                                k: Some(hex::encode(k)),
                                test_passed: None,
                            }
                        }
                        Function::Decapsulation => {
                            let dk = decode_hex(test.dk.as_deref(), "dk")?;
                            let c = decode_hex(test.c.as_deref(), "c")?;
                            let results = subprocess.transact(
                                "ML-KEM/decaps",
                                &[group.parameter_set.as_bytes(), &dk, &c],
                            )?;
                            if subprocess.check_unsupported(
                                &results,
                                &format!("ML-KEM/decaps for parameterSet={}", group.parameter_set),
                            ) {
                                continue;
                            }
                            let k = one_result(&results, "ML-KEM/decaps")?;
                            ResponseTest {
                                tc_id: test.tc_id,
                                ek: None,
                                dk: None,
                                c: None,
                                k: Some(hex::encode(k)),
                                test_passed: None,
                            }
                        }
                        Function::EncapsulationKeyCheck => {
                            let ek = decode_hex(test.ek.as_deref(), "ek")?;
                            let results = subprocess.transact(
                                "ML-KEM/encapsulationKeyCheck",
                                &[group.parameter_set.as_bytes(), &ek],
                            )?;
                            if subprocess.check_unsupported(
                                &results,
                                &format!(
                                    "ML-KEM/encapsulationKeyCheck for parameterSet={}",
                                    group.parameter_set
                                ),
                            ) {
                                continue;
                            }
                            let passed = check_passed(one_result(
                                &results,
                                "ML-KEM/encapsulationKeyCheck",
                            )?)?;
                            ResponseTest {
                                tc_id: test.tc_id,
                                ek: None,
                                dk: None,
                                c: None,
                                k: None,
                                test_passed: Some(passed),
                            }
                        }
                        Function::DecapsulationKeyCheck => {
                            let dk = decode_hex(test.dk.as_deref(), "dk")?;
                            let results = subprocess.transact(
                                "ML-KEM/decapsulationKeyCheck",
                                &[group.parameter_set.as_bytes(), &dk],
                            )?;
                            if subprocess.check_unsupported(
                                &results,
                                &format!(
                                    "ML-KEM/decapsulationKeyCheck for parameterSet={}",
                                    group.parameter_set
                                ),
                            ) {
                                continue;
                            }
                            let passed = check_passed(one_result(
                                &results,
                                "ML-KEM/decapsulationKeyCheck",
                            )?)?;
                            ResponseTest {
                                tc_id: test.tc_id,
                                ek: None,
                                dk: None,
                                c: None,
                                k: None,
                                test_passed: Some(passed),
                            }
                        }
                    }
                }
            };
            response_tests.push(response_test);
        }
        response_groups.push(ResponseGroup {
            tg_id: group.tg_id,
            tests: response_tests,
        });
    }
    serde_json::to_value(Response {
        vs_id: vector_set.vs_id,
        algorithm: vector_set.algorithm,
        revision: vector_set.revision,
        test_groups: response_groups,
    })
    .context("Failed to serialize ML-KEM response")
}

#[cfg(test)]
mod tests {
    use super::super::Subprocess;
    use super::process_mlkem;
    use serde_json::json;
    use std::path::Path;

    // FIPS-203 ML-KEM-512 known-answer test vectors (TC 1)
    const Z: &str = "84CC9121AE56FBF39E67ADBD83AD2D3E3BB80843645206BDD9F2F629E3CC49B7";
    const D: &str = "2CB843A02EF02EE109305F39119FABF49AB90A57FFECB3A0E75E179450F52761";
    const EK_KEYGEN: &str = "A32439F85A3C21D21A71B9B92A9B64EA0AB84312C77023694FD64EAAB907A43539DDB27BA0A853CC9069EAC8508C653E600B2AC018381B4BB4A879ACDAD342F91179CA8249525CB1968BBE52F755B7F5B43D6663D7A3BF0F3357D8A21D15B52DB3818ECE5B402A60C993E7CF436487B8D2AE91E6C5B88275E75824B0007EF3123C0AB51B5CC61B9B22380DE66C5B20B060CBB986F8123D94060049CDF8036873A7BE109444A0A1CD87A48CAE54192484AF844429C1C58C29AC624CD504F1C44F1E1347822B6F221323859A7F6F754BFE710BDA60276240A4FF2A5350703786F5671F449F20C2A95AE7C2903A42CB3B303FF4C427C08B11B4CD31C418C6D18D0861873BFA0332F11271552ED7C035F0E4BC428C43720B39A65166BA9C2D3D770E130360CC2384E83095B1A159495533F116C7B558B650DB04D5A26EAAA08C3EE57DE45A7F88C6A3CEB24DC5397B88C3CEF003319BB0233FD692FDA1524475B351F3C782182DECF590B7723BE400BE14809C44329963FC46959211D6A623339537848C251669941D90B130258ADF55A720A724E8B6A6CAE3C2264B1624CCBE7B456B30C8C7393294CA5180BC837DD2E45DBD59B6E17B24FE93052EB7C43B27AC3DC249CA0CBCA4FB5897C0B744088A8A0779D32233826A01DD6489952A4825E5358A700BE0E179AC197710D83ECC853E52695E9BF87BB1F6CBD05B02D4E679E3B88DD483B0749B11BD37B383DCCA71F9091834A1695502C4B95FC9118C1CFC34C84C2265BBBC563C282666B60AE5C7F3851D25ECBB5021CC38CB73EB6A3411B1C29046CA66540667D136954460C6FCBC4BC7C049BB047FA67A63B3CC1111C1D8AC27E8058BCCA4A15455858A58358F7A61020BC9C4C17F8B95C268CCB404B9AAB4A272A21A70DAF6B6F15121EE01C156A354AA17087E07702EAB38B3241FDB553F657339D5E29DC5D91B7A5A828EE959FEBB90B07229F6E49D23C3A190297042FB43986955B69C28E1016F77A58B431514D21B888899C3608276081B75F568097CDC1748F32307885815F3AEC9651819AA6873D1A4EB83B1953843B93422519483FEF0059D36BB2DB1F3D468FB068C86E8973733C398EAF00E1702C6734AD8EB3B";
    // encapsulation inputs
    const EK_ENCAPS: &str = "DD1924935AA8E617AF18B5A065AC45727767EE897CF4F9442B2ACE30C0237B307D3E76BF8EEB78ADDC4AACD16463D8602FD5487B63C88BB66027F37D0D614D6F9C24603C42947664AC4398C6C52383469B4F9777E5EC7206210F3E5A796BF45C53268E25F39AC261AF3BFA2EE755BEB8B67AB3AC8DF6C629C1176E9E3B965E9369F9B3B92AD7C20955641D99526FE7B9FE8C850820275CD964849250090733CE124ECF316624374BD18B7C358C06E9C136EE1259A9245ABC55B964D689F5A08292D28265658EBB40CBFE488A2228275590AB9F32A34109709C1C291D4A23337274C7A5A5991C7A87B81C974AB18CE77859E4995E7C14F0371748B7712FB52C5966CD63063C4F3B81B47C45DDE83FB3A2724029B10B3230214C04FA0577FC29AC9086AE18C53B3ED44E507412FCA04B4F538A51588EC1F1029D152D9AE7735F76A077AA9484380AED9189E5912487FCC5B7C7012D9223DD967EECDAC3008A8931B648243537F548C171698C5B381D846A72E5C92D4226C5A8909884F1C4A3404C1720A5279414D7F27B2B982652B6740219C56D217780D7A5E5BA59836349F726881DEA18EF75C0772A8B922766953718CACC14CCBACB5FC412A2D0BE521817645AB2BF6A4785E92BC94CAF477A967876796C0A5190315AC0885671A4C749564C3B2C7AED9064EBA299EF214BA2F40493667C8BD032AEC5621711B41A3852C5C2BAB4A349CE4B7F085A812BBBC820B81BEFE63A05B8BCDFE9C2A70A8B1ACA9BF9816481907FF4432461111287303F0BD817C05726BFA18A2E24C7724921028032F622BD960A317D83B356B57F4A8004499CBC73C97D1EB7745972631C0561C1A3AB6EF91BD363280A10545DA693E6D58AED6845E7CC5F0D08CA7905052C77366D1972CCFCC1A27610CB543665AA798E20940128B9567A7EDB7A900407C70D359438435E13961608D552A94C5CDA7859220509B483C5C52A210E9C812BC0C2328CA00E789A56B2606B90292E3543DACAA2431841D61A22CA90C1CCF0B5B4E0A6F640536D1A26AB5B8D2151327928CE02904CF1D15E32788A95F62D3C270B6FA1508F97B9155A2726D80A1AFA3C5387A276A4D031A08ABF4F2E74F1A0BB8A0FD3CB";
    const M: &str = "6FF02E1DC7FD911BEEE0C692C8BD100C3E5C48964D31DF92994218E80664A6CA";
    const CT: &str = "19C592505907C24C5FA2EBFA932D2CBB48F3E4340A28F7EBA5D068FCACABEDF77784E2B24D7961775F0BF1A997AE8BA9FC4311BE63716779C2B788F812CBB78C74E7517E22E910EFF5F38D44469C50DE1675AE198FD6A289AE7E6C30A9D4351B3D1F4C36EFF9C68DA91C40B82DC9B2799A33A26B60A4E70D7101862779469F3A9DAEC8E3E8F8C6A16BF092FBA5866186B8D208FDEB274AC1F829659DC2BE4AC4F306CB5584BAD1936A92C9B76819234281BB395841C25756086EA564CA3E227E3D9F1052C0766D2EB79A47C150721E0DEA7C0069D551B264801B7727ECAF82EECB99A876FDA090BF6C3FC6B109F1701485F03CE66274B8435B0A014CFB3E79CCED67057B5AE2AD7F5279EB714942E4C1CCFF7E85C0DB43E5D41289207363B444BB51BB8AB0371E70CBD55F0F3DAD403E105176E3E8A225D84AC8BEE38C821EE0F547431145DCB3139286ABB11794A43A3C1B5229E4BCFE959C78ADAEE2D5F2497B5D24BC21FA03A9A58C2455373EC89583E7E588D7FE67991EE93783ED4A6F9EEAE04E64E2E1E0E699F6DC9C5D39EF9278C985E7FDF2A764FFD1A0B95792AD681E930D76DF4EFE5D65DBBD0F1438481ED833AD4946AD1C69AD21DD7C86185774426F3FCF53B52AD4B40D228CE124072F592C7DAA057F17D790A5BD5B93834D58C08C88DC8F0EF488156425B744654EACA9D64858A4D6CEB478795194BFADB18DC0EA054F9771215AD3CB1FD031D7BE4598621926478D375A1845AA91D7C733F8F0E188C83896EDF83B8646C99E29C0DA2290E71C3D2E970720C97B5B7F950486033C6A2571DDF2BCCDABB2DFA5FCE4C3A1884606041D181C728794AE0E806ECB49AF16756A4CE73C87BD4234E60F05535FA5929FD5A34473266401F63BBD6B90E003472AC0CE88F1B666597279D056A632C8D6B790FD411767848A69E37A8A839BC766A02CA2F695EC63F056A4E2A114CACF9FD90D730C970DB387F6DE73395F701A1D953B2A89DD7EDAD439FC205A54A481E889B098D5255670F026B4A2BF02D2BDDE87C766B25FC5E0FD453757E756D18C8CD912F9A77F8E6BF0205374B462";
    const K_ENCAPS: &str = "0BF323338D6F0A21D5514B673CD10B714CE6E36F35BCD1BF544196368EE51A13";
    // decapsulation uses a different DK/CT pair from the test suite
    const DK_DECAPS: &str = "54301038DA5911366D16C417BFD96AEB85C5DA4AA45AF32F88A700BB9A973AB62684A052D793379B3C2B253B01A4E512AB34C8D8A76F5EBA5F1B28451A66632872C489F3CA606C6B36336895C032386BB35E98B43C8136350616CCF82A4C24816F4354B7C197940A62537BB36F2B8DE32A6AF6CAA100845FB62184B82B29DCE2662CA94D93FB027DB3C8EF858D4223540E79AD5D204C99637FB66718CD04782E149A07354D6FB2C742A9849506BDDECC0548367421FA2B8599443C74192D6B4B67CC5E16F8880087AC578ABCADB5492CC1AC6916CE73AB2858797134676260B22B28B4A8917C5ABD876EDA706CE381AA4985827D492A736652DD6C1DADD10ADF045DBF416158B0384A991D8501BAA9A714B82788C263C16858C81B978FD353126222A46E1587718872BB11513CDA3A88B6547BC464CD612548E581DFE106382428BA8452A86AC6ECB50B7B3C1CBEA571513C63B8741A2CB82C5055CDB2CB00CE9036C220A25C1BA21891B520D435342136D0C15AAFC12DBCC810E9C256D397A3D23A6287282AAEC038649151886A19F9B583806839EE86A12D131FB3E6A1CA1C9CC48626037B5F3DA74C8A025CC61A76078B07D00AA6DAD32C4147CDAADB4DF644A8DBF4222C47AEEF774BDAFA5A48258BDEA84E7B8B6A5CA09243589EF7F1C249A2B344068FC8D874C33B6C4C2782EA86AADE7C10EFDCC93FB993147A3B636127711195C121C7506759389373F896843991125D5A0AB8FB34595166A9109DC2D19AE2738444716C9C21BD06DC8145458ACBA30981A95F8E141BD17B17A3F645E9B63747E370E8D873937A858048614F0645F4B461EF769D2A696706C2811E756163E4746BF00CFFC556AD7A2F0804A6BEDC6A59B1546727C602A99397C50FF818721D5319F63B058D03BC9DE57C1DB74FE14A0D083C25B17886200633D230946DE0A148781735555CCE797040BB479FA733C2A808EE1CB9A285CF863CBDB47172F3A68EEA614736C73C71FA4AD82C6CF13C5CD3179AD296BF3BD6815D13CBFF75A3A99B4824B7560227BE0BD809BD43AED7D951ECDB7273719560DCC0E8C13F70EC19B39348974173A550A5C52A248E191D46640799A4365F3C254757350B65764984180A9ABC9048679D6A84C61B7405EC82A403B79569C024CACA55D79BE23C943C159DDADB17011820C7D88D54071FC8AB142727BE747BBD253A26E92071DC34716F5037D1988A889302621A8465D08ABFD2215D97575D730C9495617EF3B69D0C7AA79965CA985BC147797D9688116A20F9626BAB1997FCEAACBFB439D655A566B0A4BD08472265439C00CE487955EBEA094AD00A6A5AC6FB9359F3C11A6E4B3B6C714F70F8A7B8B6524572B34B758DA270753B697415A964170374548B9D1FE43FD80C62A4D951E28182F2848B044A8352E11F5198547B71215E6287DFF13A18287148277883926396D9A07C0B0139577E4923AC41C9C31F0B6067C88B94CBB9921513ACF0AE80D7779D72C666B256B72A777B56A2D12007797B7BE6657650EB42B1060AADC5157FB819EBF707E51637CD8469645196765A2EBFE8483D62C5E2422C27BCA84E5A0F69F45609928A7E51948A9464D5093CF463A39C26447126C684160F3A4298EA0B5B0973A15403CDDF286BEBFA587FFBB5BFA7692A404ABE3BB14014AEAC418900E4588676A5E7A21553F50037262E3DD6253A8BBD985A679F638F709545AB322F6DE71192FB60C0A368A3B06C8CF5267D792D6C2518EA0A27855635E3E68891C141123A1F8C80AA5300B151AC9AE4342334265C457CA8809891EFF12B398A8465F25508836EE3075C898822BA7675AC359D80E85FF84112C8502932016E24531FB24AA0F744B8252B3D89B4A41721BFD779A826AA46F00720B9592A12307B27EB2B5502987AB477161B72F31BB8EF2C2F4EA83823B72CB16532768508835852A701C3522A7B71DA1CD8B5CCA512117990709797C8AAEA3B300B79A28460D22A2C3527CBB8529AA667064FA2039E22AD5ED740BFA353EB04B74A9C9328266561A76A12EC2C33766697DABBDE92A712B81712D2C4E1F335AA642774441E917650F8D92278A8C0444214A774B7996463527756935171D9FA61D0B50454F74ED50831EB3138DB7374A35387BBCB23E40388BB9228C3A66CDD2222524D7CB8DAE2E70FE3D97847AC35824F5D58B54DD943A440DBFF4216429146E2AC9383962420545163D6F82456E1B93E22A1B2E6875ADA12D4E194AE93EF5C3485EEBBE1BB13C560480DC3471CD950EB300CF2D18F38CAE7575B133526";
    const CT_DECAPS: &str = "9068502093766BB27635F12F3569794C54227CB1828128AEFC5B715CDCD1E9080D59FB218D17EA0D212D158DDB5ED0FFDB4FA9401F4F23387D32AC8B788CFB7A319114425138744002648B07D5216A3EFB4964BC72E98A6EA2939FAF372CAB44CD5D8A929F66C41D644118ACDE5DA2F09B87F8A1F41F55924A7784D8552790CDF256958E35324381902D9A006FAE02933B017A8E55931B6A0CC8CE3B5723D85DE4C4585FAEC0BD80986224CDAEA443556EBF8BCFDE162C258B9E0AB00C2B9DE0190384C61988BCF362BD0493D40D276FFE4873811EF2851204626342921BFB6A75EB6079F58C030AB1D9C1844078E61C29DB88B5FDC463B7AD3F770E1CB8B526BD9B9A5AFADADAED0368BEE0FFABD9ADFEB0FBF6E6DC7A36115BA47A292D454D7A31F5601BD8BD5435B2EF464A474E37B12B7794F356F905FDBEB248B44003F2B43B925CDB98017A68A15B8B90E2D6DAB1B72AC2921CA92F55B3453C2865DECC094E77EC1E70F99A14CE22BBBF7D3C25F1ECBF96478D84DB4EB1F5E077777214CDA31165C2790172EF778435B56B712E3C5C6B2FDFA3B40B45F7065731EC1E33A8FB300F9FD1EAB14A77E5D8367329E0F834A76E889EC2C8F80E5C1098055F2D517EC381A01F37B1AA3923894D90E1A25A8F55D3DB782ADCD644A1B8A168BBF263C77F34B1A3388E76528FD4F91BFDD7D6499EF99CF663964421FFBB6C17CA9456A2E6A3681298628FA728D3FCFB3BDB65A22E7CFC962FB83007F249D543696A8EFBD9A3DBC7C090F2C82B38E76ACB653F18E78407EFDEA120AE61CDCC8C28CAD984D776B69FB201BA3E154F3C87F53CF84DEF777E50BE420DDFB9734065B8D541F983E69E7FB2B48A186BF8338F3234A0B785B2BA63AA875B28EEE98843C48F60BA500E93067F283155A21905836AC33CA8B06790DD800DD000CC42171775A07F704229FB6F9E5123ED032148DD0EC616530B98A68BE3DBAD2A5D24FFABEFD6D78F4484C8A9969DB7480F54A3DDAB445D3C6C489A9E296B612591A027D624032CD1B11452FEA69A178006E8429BEAB1FC089098BE7EA3D73518F3F5E7B59843";
    const K_DECAPS: &str = "32FE0534E517EC8F87A25578EA047417EC479EECE897D2BA5F9D41A521FAEDCC";

    fn start_wrapper() -> Subprocess {
        // CARGO_BIN_EXE_* is only available in integration tests; for unit tests
        // we locate the binary relative to the running test executable.
        let mut path = std::env::current_exe().expect("cannot resolve test exe");
        path.pop(); // remove test binary name
        if path.ends_with("deps") {
            path.pop(); // step out of deps/ into target/debug (or release)
        }
        path.push("mlkem_wrapper");
        Subprocess::new(Path::new(&path), None)
            .unwrap_or_else(|e| panic!("failed to start mlkem_wrapper at {path:?}: {e}"))
    }

    fn keygen_vs() -> serde_json::Value {
        json!({
            "vsId": 1,
            "algorithm": "ML-KEM",
            "mode": "keyGen",
            "revision": "FIPS203",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-KEM-512",
                "tests": [{"tcId": 1, "z": Z, "d": D}]
            }]
        })
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn keygen_produces_expected_keys() {
        let result = process_mlkem(&mut start_wrapper(), &keygen_vs()).unwrap();
        let t = &result["testGroups"][0]["tests"][0];
        assert_eq!(t["ek"].as_str().unwrap().to_uppercase(), EK_KEYGEN);
        // FIPS-203 dk layout: pke_dk (384*k bytes) ‖ ek ‖ H(ek) ‖ z
        // For ML-KEM-512: pke_dk = 768 bytes = 1536 hex chars; ek follows immediately.
        let dk = t["dk"].as_str().unwrap().to_uppercase();
        assert_eq!(&dk[1536..1536 + EK_KEYGEN.len()], EK_KEYGEN);
    }

    #[test]
    fn keygen_response_contains_required_fields() {
        let result = process_mlkem(&mut start_wrapper(), &keygen_vs()).unwrap();
        assert_eq!(result["vsId"], 1);
        assert_eq!(result["algorithm"], "ML-KEM");
        let t = &result["testGroups"][0]["tests"][0];
        assert_eq!(t["tcId"], 1);
        assert!(t["ek"].is_string());
        assert!(t["dk"].is_string());
        // ek = 800 bytes → 1600 hex chars; dk = 1632 bytes → 3264 hex chars
        assert_eq!(t["ek"].as_str().unwrap().len(), 1600);
        assert_eq!(t["dk"].as_str().unwrap().len(), 3264);
    }

    #[test]
    fn encapsulation_produces_expected_ct_and_shared_secret() {
        let vs = json!({
            "vsId": 2,
            "algorithm": "ML-KEM",
            "mode": "encapDecap",
            "revision": "FIPS203",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-KEM-512",
                "function": "encapsulation",
                "tests": [{"tcId": 1, "ek": EK_ENCAPS, "m": M}]
            }]
        });
        let result = process_mlkem(&mut start_wrapper(), &vs).unwrap();
        let t = &result["testGroups"][0]["tests"][0];
        assert_eq!(t["c"].as_str().unwrap().to_uppercase(), CT);
        assert_eq!(t["k"].as_str().unwrap().to_uppercase(), K_ENCAPS);
    }

    #[test]
    fn decapsulation_recovers_shared_secret() {
        let vs = json!({
            "vsId": 3,
            "algorithm": "ML-KEM",
            "mode": "encapDecap",
            "revision": "FIPS203",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-KEM-512",
                "function": "decapsulation",
                "tests": [{"tcId": 1, "dk": DK_DECAPS, "c": CT_DECAPS}]
            }]
        });
        let result = process_mlkem(&mut start_wrapper(), &vs).unwrap();
        let t = &result["testGroups"][0]["tests"][0];
        assert_eq!(t["k"].as_str().unwrap().to_uppercase(), K_DECAPS);
    }

    #[test]
    fn encapsulation_key_check_accepts_valid_ek() {
        let vs = json!({
            "vsId": 4,
            "algorithm": "ML-KEM",
            "mode": "encapDecap",
            "revision": "FIPS203",
            "testGroups": [{
                "tgId": 1,
                "parameterSet": "ML-KEM-512",
                "function": "encapsulationKeyCheck",
                "tests": [{"tcId": 1, "ek": EK_KEYGEN}]
            }]
        });
        let result = process_mlkem(&mut start_wrapper(), &vs).unwrap();
        assert_eq!(result["testGroups"][0]["tests"][0]["testPassed"], true);
    }

    #[test]
    fn decapsulation_key_check_accepts_valid_dk() {
        let result = process_mlkem(&mut start_wrapper(), &keygen_vs()).unwrap();
        let dk = result["testGroups"][0]["tests"][0]["dk"]
            .as_str()
            .unwrap()
            .to_string();

        let vs = json!({
            "vsId": 5,
            "algorithm": "ML-KEM",
            "mode": "encapDecap",
            "revision": "FIPS203",
            "testGroups": [{
                "tgId": 1,
                "parameterSet": "ML-KEM-512",
                "function": "decapsulationKeyCheck",
                "tests": [{"tcId": 1, "dk": dk}]
            }]
        });
        let result2 = process_mlkem(&mut start_wrapper(), &vs).unwrap();
        assert_eq!(result2["testGroups"][0]["tests"][0]["testPassed"], true);
    }

    #[test]
    fn multiple_test_groups_processed_independently() {
        let vs = json!({
            "vsId": 6,
            "algorithm": "ML-KEM",
            "mode": "encapDecap",
            "revision": "FIPS203",
            "testGroups": [
                {
                    "tgId": 1,
                    "parameterSet": "ML-KEM-512",
                    "function": "encapsulation",
                    "tests": [{"tcId": 1, "ek": EK_ENCAPS, "m": M}]
                },
                {
                    "tgId": 2,
                    "parameterSet": "ML-KEM-512",
                    "function": "decapsulation",
                    "tests": [{"tcId": 2, "dk": DK_DECAPS, "c": CT_DECAPS}]
                }
            ]
        });
        let result = process_mlkem(&mut start_wrapper(), &vs).unwrap();
        let groups = result["testGroups"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["tgId"], 1);
        assert_eq!(groups[1]["tgId"], 2);
        assert!(groups[0]["tests"][0]["c"].is_string());
        assert!(groups[1]["tests"][0]["k"].is_string());
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn encapsulation_key_check_rejects_all_ff_bytes() {
        // All-0xFF bytes decode to NTT coefficients of 4095 > q=3329; the
        // canonical re-encoding differs, so check_ek must return false.
        let invalid_ek = "ff".repeat(800);
        let vs = json!({
            "vsId": 10,
            "algorithm": "ML-KEM",
            "mode": "encapDecap",
            "revision": "FIPS203",
            "testGroups": [{
                "tgId": 1,
                "parameterSet": "ML-KEM-512",
                "function": "encapsulationKeyCheck",
                "tests": [{"tcId": 1, "ek": invalid_ek}]
            }]
        });
        let result = process_mlkem(&mut start_wrapper(), &vs).unwrap();
        assert_eq!(result["testGroups"][0]["tests"][0]["testPassed"], false);
    }

    #[test]
    fn decapsulation_key_check_rejects_all_ff_bytes() {
        // The stored H(ek) inside an all-0xFF dk won't match SHA3-256 of the
        // embedded ek bytes, so check_dk must return false.
        let invalid_dk = "ff".repeat(1632);
        let vs = json!({
            "vsId": 11,
            "algorithm": "ML-KEM",
            "mode": "encapDecap",
            "revision": "FIPS203",
            "testGroups": [{
                "tgId": 1,
                "parameterSet": "ML-KEM-512",
                "function": "decapsulationKeyCheck",
                "tests": [{"tcId": 1, "dk": invalid_dk}]
            }]
        });
        let result = process_mlkem(&mut start_wrapper(), &vs).unwrap();
        assert_eq!(result["testGroups"][0]["tests"][0]["testPassed"], false);
    }

    #[test]
    fn encapsulation_key_check_rejects_wrong_length() {
        // A key that is one byte short fails the length check immediately.
        let short_ek = "aa".repeat(799);
        let vs = json!({
            "vsId": 12,
            "algorithm": "ML-KEM",
            "mode": "encapDecap",
            "revision": "FIPS203",
            "testGroups": [{
                "tgId": 1,
                "parameterSet": "ML-KEM-512",
                "function": "encapsulationKeyCheck",
                "tests": [{"tcId": 1, "ek": short_ek}]
            }]
        });
        let result = process_mlkem(&mut start_wrapper(), &vs).unwrap();
        assert_eq!(result["testGroups"][0]["tests"][0]["testPassed"], false);
    }

    #[test]
    fn unknown_mode_returns_error() {
        let vs = json!({
            "vsId": 20,
            "algorithm": "ML-KEM",
            "mode": "badMode",
            "revision": "FIPS203",
            "testGroups": [{
                "tgId": 1,
                "parameterSet": "ML-KEM-512",
                "tests": [{"tcId": 1, "z": Z, "d": D}]
            }]
        });
        assert!(process_mlkem(&mut start_wrapper(), &vs).is_err());
    }

    #[test]
    fn unknown_function_in_encapdecap_returns_error() {
        let vs = json!({
            "vsId": 21,
            "algorithm": "ML-KEM",
            "mode": "encapDecap",
            "revision": "FIPS203",
            "testGroups": [{
                "tgId": 1,
                "parameterSet": "ML-KEM-512",
                "function": "badFunction",
                "tests": [{"tcId": 1, "ek": EK_ENCAPS}]
            }]
        });
        assert!(process_mlkem(&mut start_wrapper(), &vs).is_err());
    }

    #[test]
    fn missing_mode_field_returns_error() {
        let vs = json!({
            "vsId": 22,
            "algorithm": "ML-KEM",
            "revision": "FIPS203",
            "testGroups": [{"tgId": 1, "parameterSet": "ML-KEM-512", "tests": []}]
        });
        assert!(process_mlkem(&mut start_wrapper(), &vs).is_err());
    }

    #[test]
    fn missing_seed_z_returns_error() {
        let vs = json!({
            "vsId": 23,
            "algorithm": "ML-KEM",
            "mode": "keyGen",
            "revision": "FIPS203",
            "testGroups": [{
                "tgId": 1,
                "parameterSet": "ML-KEM-512",
                "tests": [{"tcId": 1, "d": D}]  // z is absent
            }]
        });
        assert!(process_mlkem(&mut start_wrapper(), &vs).is_err());
    }

    #[test]
    fn invalid_hex_in_seed_returns_error() {
        let vs = json!({
            "vsId": 24,
            "algorithm": "ML-KEM",
            "mode": "keyGen",
            "revision": "FIPS203",
            "testGroups": [{
                "tgId": 1,
                "parameterSet": "ML-KEM-512",
                "tests": [{"tcId": 1, "z": "ZZZZNOTHEX!", "d": D}]
            }]
        });
        assert!(process_mlkem(&mut start_wrapper(), &vs).is_err());
    }

    #[test]
    fn missing_function_field_in_encapdecap_returns_error() {
        let vs = json!({
            "vsId": 25,
            "algorithm": "ML-KEM",
            "mode": "encapDecap",
            "revision": "FIPS203",
            "testGroups": [{
                "tgId": 1,
                "parameterSet": "ML-KEM-512",
                // function field absent
                "tests": [{"tcId": 1, "ek": EK_ENCAPS}]
            }]
        });
        assert!(process_mlkem(&mut start_wrapper(), &vs).is_err());
    }
}
