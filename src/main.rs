#[macro_use]
extern crate lazy_static;

use anyhow::anyhow;
use chacha20poly1305::{
    aead::{Aead, NewAead, AeadInPlace, Buffer},
    XChaCha20Poly1305,
};

use clap::{arg, command, value_parser};
use rand::{rngs::OsRng, RngCore};
use std::{path::PathBuf, fs::OpenOptions};
use std::{
    fs::{self},
    io::{Read, Write},
};


lazy_static!{
    static ref KEY:[u8; 32] = {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    };
    static ref NONCE:[u8; 24] = {
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        nonce
    };
}
fn read_or_create_file(file_path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if fs::metadata(file_path).is_ok() {
        let mut file = fs::File::open(file_path)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        Ok(contents)

    } else {
        let mut v = Vec::new();
        v.extend_from_slice(KEY.as_slice());
        v.extend_from_slice(NONCE.as_slice());
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)?;
        let mut file = std::io::BufWriter::new(file);
        file.write(&KEY.as_slice())?;
        file.write(&NONCE.as_slice())?;
        Ok(v)
    }
}

fn main() {
    let seeds = read_or_create_file("./.seed").unwrap();
    // println!("{:?}", seeds.len());
    let (_key, _nonce)= seeds.split_at(32);
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    key.copy_from_slice(_key);
    nonce.copy_from_slice(_nonce);
    println!("{:?}", key);


    let matches = command!() // requires `cargo` feature
        .arg(arg!([name] "Путь до файла"))
        .arg(
            arg!(
                -p --prepare <FILE> "Путь до файла для шифровки"
            )
            // We don't have syntax yet for optional options, so manually calling `required`
            .required(false)
            .value_parser(value_parser!(PathBuf)),
        )
        // .arg(arg!( -d --debug ... "Turn debugging information on"))
        .arg(arg!(-r --read <FILE> "Получает путь на шифрованный файл и выводит в консоль его содержимое")
             .required(false)
             .value_parser(value_parser!(PathBuf)))
        .arg(arg!(-d --decrypt <FILE> "Получает путь на файл и расшифровывает его заменяя содержимое на читаемый формат")
             .required(false)
             .value_parser(value_parser!(PathBuf)))
        
        .get_matches();
    if let Some(config_path) = matches.get_one::<PathBuf>("prepare") {
        println!("Value for config: {}", config_path.display());
        let _ = encrypt_file(config_path.into(), config_path.into(), &key, &nonce);
    }
    if let Some(config_path) = matches.get_one::<PathBuf>("read") {
        println!("Value for config: {}", config_path.display());
        let cont = read_content(config_path.into(), &key, &nonce);
        println!("{:?}", cont);
    }
    if let Some(config_path) = matches.get_one::<PathBuf>("decrypt") {
        println!("Value for config: {}", config_path.display());
        let _ = decrypt_file(config_path.into(),config_path.into(),  &key, &nonce);
    }
 
}

fn read_content(
    filepath: PathBuf,
    key: &[u8; 32],
    nonce: &[u8; 24]
    ) -> Result<String, Box<dyn std::error::Error>>
{
    // println!("asdasd");
    let cipher = XChaCha20Poly1305::new(key.into());

    let file_data = fs::read(filepath)?;
    let decrypt_text = cipher.decrypt(nonce.into(), file_data.as_ref())
        .map_err(|err| ("Can't read a file content, error: {:?}", err)).unwrap();
        
   Ok(String::from_utf8(decrypt_text.clone()).unwrap())
}


fn encrypt_file(
    filepath: PathBuf,
    dist: PathBuf,
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<(), anyhow::Error> {
    
    let cipher = XChaCha20Poly1305::new(key.into());

    let file_data = fs::read(filepath)?;

    let encrypted_file = cipher
        .encrypt(nonce.into(), file_data.as_ref())
        .map_err(|err| anyhow!("No such a file: {}", err))?;
    // println!("{:?}", encrypted_file);

    fs::write(&dist, encrypted_file)?;

    Ok(())
}

fn decrypt_file(
    encrypted_file_path: PathBuf,
    dist: PathBuf,
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<(), anyhow::Error> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let file_data = fs::read(encrypted_file_path)?;

    let decrypted_file = cipher
        .decrypt(nonce.into(), file_data.as_ref()).unwrap();
    println!("asdasd");

    fs::write(&dist, decrypted_file)?;

    Ok(())
}
