use base64;
use xmltree::Element;
use regex::Regex;
use base64::{Engine as _, engine::general_purpose};
use base64_url;
use rand::Rng;
use sha256;
use jws::JsonObject;
use chrono::Utc;

pub fn to_hex(num: u32) -> String {
    let hex = format!("{:x}", num);
    if hex.len() < 2 {
        return format!("0{}", hex);
    } else {
        return hex;
    }
}

fn encode_length_hex(num: u32) -> String {
    if num <= 127 {
        return to_hex(num);
    }
    let n_hex = to_hex(num);
    let b_len = 128u32 + (n_hex.len() as u32) / 2;
    return vec![to_hex(b_len), n_hex].into_iter().collect();
}

fn prepad_signed(hex_str: String) -> String {
    if let Some(msb) = hex_str.chars().next() {
        if let Some(num) = msb.to_digit(10) {
            if num == 0 || num > 7 {
                return vec![String::from("00"), hex_str].into_iter().collect();
            }
        }
    }
    return hex_str;
}

pub fn rsa_pub_key_pem(modulus: &str, exponent: &str) -> String {
    let h_mod: String = prepad_signed(
        modulus
                .as_bytes()
                .iter()
                .map(|c| format!("{:02x}", c))
                .collect()
    );

    let h_exp: String = prepad_signed(
        exponent
            .as_bytes()
            .iter()
            .map(|c| format!("{:02x}", c))
            .collect()
    );

    let mod_len = (h_mod.len() as u32) / 2;
    let exp_len = (h_exp.len() as u32) / 2;

    let enc_mod_len = encode_length_hex(mod_len);
    let enc_exp_len = encode_length_hex(exp_len);

    let encoded_pub_key: String = vec![
        String::from("30"),
        encode_length_hex(
            mod_len +
            exp_len +
            (enc_mod_len.len() as u32) / 2 +
            (enc_exp_len.len() as u32) / 2 + 2
        ),
        String::from("02"),
        enc_mod_len,
        h_mod,
        String::from("02"),
        enc_exp_len,
        h_exp
    ].into_iter().collect();

    let der_b64 = general_purpose::STANDARD.encode(encoded_pub_key);

    let re = Regex::new(r".{1,64}").unwrap();
    let encoded: Vec<String> = re.find_iter(der_b64.as_str()).map(|m| String::from(m.as_str())).collect();
    let pem = vec![
        String::from("-----BEGIN RSA PUBLIC KEY-----\n"),
        encoded.join("\n"),
        String::from("\n-----END RSA PUBLIC KEY-----\n")
    ].join("");
    pem
}

pub fn xml_rsa_pub_key_pem(xml_cert: String) -> String {
    let cert_element = Element::parse(xml_cert.as_bytes()).unwrap();


    let c_mod = cert_element.get_child("Modulus").unwrap().get_text().unwrap();
    let c_exp = cert_element.get_child("Exponent").unwrap().get_text().unwrap();

    return rsa_pub_key_pem(c_mod.as_ref(), c_exp.as_ref());
}

pub fn uid(len: usize) -> String {
    let bytes = rand::thread_rng().gen::<[u8; 32]>();
    let value = &base64_url::encode(&bytes)[..len];
    value.to_string()
}

pub fn check_hash_rs256(content: String, hash: String) -> bool {
    if content.is_empty() {
        return false;
    }

    let digest = sha256::digest(content.clone());
    let buffer = content[..digest.len() / 2].as_bytes();
    let computed = base64_url::encode(buffer);

    return hash == computed;
}

pub fn process_array(content: Vec<JsonObject>, max_len: usize, max_age: u32) -> Vec<JsonObject> {
    let now = Utc::now().timestamp();
    content
        .into_iter()
        .filter(|e| {
            if let Some(time_stamp) = e.get("timeStamp") {
                if let serde_json::Value::Number(value) = time_stamp {
                    return value.as_i64().unwrap() + (max_age as i64) * 1000 >= now;
                } else {
                    return false;
                }
            }
            return false;
        })
        .take(max_len)
        .collect()
}

pub fn concat_url(url: String, rest: Vec<String>) -> String {
    let mut first_mark = "?";

    if url.contains("?") {
        first_mark = "&";
    }

    return vec![
        url,
        first_mark.to_string(),
        rest.join("&")
    ].join("");
}

pub fn same_site_not_allowed(user_agent: &str) -> bool {
    // Cover all iOS based browsers here. This includes:
    // - Safari on iOS 12 for iPhone, iPod Touch, iPad
    // - WkWebview on iOS 12 for iPhone, iPod Touch, iPad
    // - Chrome on iOS 12 for iPhone, iPod Touch, iPad
    // All of which are broken by SameSite=None, because they use the iOS networking stack
    if user_agent.contains("CPU iPhone OS 12") || user_agent.contains("iPad; CPU OS 12") {
      return true;
    }   
    // Cover Mac OS X based browsers that use the Mac OS networking stack. This includes:
    // - Safari on Mac OS X
    // - Internal browser on Mac OS X
    // This does not include:
    // - Chrome on Mac OS X
    // - Chromium on Mac OS X
    // Because they do not use the Mac OS networking stack.
    if user_agent.contains("Macintosh; Intel Mac OS X 10_14") && !user_agent.contains("Chrome/") && !user_agent.contains("Chromium") {
      return true;
    }   
    // Cover Chrome 50-69, because some versions are broken by SameSite=None, and none in this range require it.
    // Note: this covers some pre-Chromium Edge versions, but pre-Chromim Edge does not require SameSite=None, so this is fine.
    // Note: this regex applies to Windows, Mac OS X, and Linux, deliberately.
    if user_agent.contains("Chrome/5") || user_agent.contains("Chrome/6") {
      return true;
    }   
    // Unreal Engine runs Chromium 59, but does not advertise as Chrome until 4.23. Treat versions of Unreal
    // that don't specify their Chrome version as lacking support for SameSite=None.
    if user_agent.contains("UnrealEngine") && !user_agent.contains("Chrome") {
      return true;
    }   
    // UCBrowser < 12.13.2 ignores Set-Cookie headers with SameSite=None.
    // NB: this rule isn't complete - you need regex to make a complete rule.
    // See: https://www.chromium.org/updates/same-site/incompatible-clients
    if user_agent.contains("UCBrowser/12") || user_agent.contains("UCBrowser/11") {
      return true;
    }   

    false
}


pub fn vec_diff<T: std::cmp::PartialEq>(v1: &Vec<T>, v2: &Vec<T>) -> bool {
    if v1.len() != v2.len() {
        return true;
    }

    let mut diff: Vec<&T> = vec![];

    v1.iter().for_each(|e| {
        if !v2.contains(e) {
            diff.push(&e);
        }
    });

    if diff.len() > 0 {
        return true;
    }

    v2.iter().for_each(|e| {
        if !v1.contains(e) {
            diff.push(e);
        }
    });

    diff.len() > 0
}