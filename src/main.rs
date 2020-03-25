extern crate clap;
extern crate json;
extern crate colored;

use clap::{Arg, App};
use colored::*;

use std::env;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::{thread, time};
use std::path;
use std::io::BufReader;
use std::io::prelude::*;

fn main() {

    // clap thang
    let arg_matches = App::new("certdiff")
        .version("0.0.1")
        .author("Sahil Tembhare @isrsahilmk")
        .about("Cert diffing tool for continuous subdomain reconnaissance. (This tool will save all the data into ~/.certdiff directory)")
        .arg(Arg::with_name("target")
            .short("t")
            .long("target")
            .value_name("target domain")
            .help("Enter the target site, you can keep track of subdomains of the target site")
            .takes_value(true)).get_matches();

      
    // checking if ~/.facediff dir exists, if not, create one
    match env::home_dir() {
   	 Some(home_path) => {
	    match fs::create_dir(home_path.join(".certdiff")) {
	        Ok(_) => (),
	        Err(_) => ()
	    }
	 },
	 None => eprintln!("{}", "[+] No home dir [+]".red())
    }


    // call the http client
    match arg_matches.value_of("target") {
        Some(target) => {
            match http_client(&target.to_string()) {
                Ok(()) => (),
                Err(_) => ()
            }
        },
        None => eprintln!("{}", "[+] Target arg not passed, see help using --help [+]".red())
    }
}


fn http_client(target: &str) -> Result<(), Box<dyn std::error::Error>> {

    let url = format!("https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names", target);
    let response = reqwest::blocking::get(&url)?.text()?;

    // json parsing
    let parsed_json = json::parse(&response).unwrap();

    if parsed_json.is_array() {
        save_subs(&target, parsed_json);
    } else {
        eprintln!("{}", "[+] It seems that you have been rate limited on cert spotter api, try again later [+]".red().bold());
    }
    
    return Ok(());
}

fn save_subs(target: &str, parsed_json: json::JsonValue) {

    match env::home_dir() {
        Some(home_path) => {
            match fs::create_dir(home_path.join(".certdiff").join(target)) {
                Ok(_) => {
                    println!("{}", format!("Directory created for {} at {} \n", target, home_path.join(".certdiff").join(target).display()).yellow());
                    thread::sleep(time::Duration::from_secs(3));

                    let mut savefile = File::create(home_path.join(".certdiff").join(target).join("savefile"))
                        .expect("Unable to create the subdomains savefile");

                    for data in parsed_json.members() {
                        for sub in data["dns_names"].members() {
                            writeln!(savefile, "{}", sub)
                                .expect("Unable to write to the savefile");
                            println!("{}", sub);
                        }
                    }
                    thread::sleep(time::Duration::from_secs(3));
                    println!(
                        "{}", format!("\n[+] The subdomains has been saved into {} [+]\n[+] Run another scan maybe after a week to check if they have new subdomains added, or removed. [+]"
                            , home_path.join(".certdiff").join(target).join("savefile").display()).green()
                        );
                },

                Err(_) => {
                    
                    // Err(_) means the savefile exists, now create one more for diffing -> tempfile
                    println!("{}", format!("[+] Directory for {} already exists [+]\n", target).yellow());
                    thread::sleep(time::Duration::from_secs(3));
                    let home_path = Some(env::home_dir().unwrap()).unwrap();
                    let mut tempfile = File::create(home_path.join(".certdiff").join(target).join("tempfile"))
                       .expect("Unable to create the subdomains savefile");

                    for data in parsed_json.members() {
                        for sub in data["dns_names"].members() {
                            writeln!(tempfile, "{}", sub)
                                .expect("Unable to write to the savefile");
                            println!("{}", sub);
                        }
                    }

                    thread::sleep(time::Duration::from_secs(3));
                    println!(
                        "{}", format!("\n[+] Diffing these subdomains with the previous scan to check for new subdomains or removed subdomains [+]\n").blue().bold()
                    );
                    thread::sleep(time::Duration::from_secs(2));
                    let sf = env::home_dir().unwrap().join(".certdiff").join(target).join("savefile");
                    let tf = env::home_dir().unwrap().join(".certdiff").join(target).join("tempfile");
                    diff_subs(sf, tf);
                }
            }
        },
        None => eprintln!("{}", "[+] No home dir [+]".red())
    }
}

fn diff_subs(savefile: path::PathBuf, tempfile: path::PathBuf) {
    let mut sf_vec = Vec::new();
    let mut tf_vec = Vec::new();

    let sf = BufReader::new(File::open(savefile).unwrap());
    let tf = BufReader::new(File::open(tempfile).unwrap());
    
    // saving sf and tf subdomains into vectors
    for line in sf.lines() {
        &sf_vec.push(line.unwrap());
    }

    for line in tf.lines() {
        &tf_vec.push(line.unwrap());
    }
    

}
