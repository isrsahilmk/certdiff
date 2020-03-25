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

      
    // checking if ~/.certdiff dir exists, if not, create one
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
                            , home_path.join(".certdiff").join(target).join("savefile").display()).blue()
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
                    diff_subs(&target);
                }
            }
        },
        None => eprintln!("{}", "[+] No home dir [+]".red())
    }
}

fn diff_subs(target: &str) {

    let sf_file = env::home_dir().unwrap().join(".certdiff").join(&target).join("savefile");
    let tf_file = env::home_dir().unwrap().join(".certdiff").join(&target).join("tempfile");

    let mut sf_vec = Vec::new();
    let mut tf_vec = Vec::new();
    let mut new_vec = Vec::new();
    let mut rem_vec = Vec::new();

    let sf_buf = BufReader::new(File::open(&sf_file).unwrap());
    let tf_buf = BufReader::new(File::open(&tf_file).unwrap());
    
    // saving sf and tf subdomains into vectors
    for line in sf_buf.lines() {
        &sf_vec.push(line.unwrap());
    }

    for line in tf_buf.lines() {
        &tf_vec.push(line.unwrap());
    }

    // removing duplicate subdomain entry
    sf_vec.dedup();
    tf_vec.dedup();
    
    // check new subdonains
    for t_sd in &tf_vec {
        if !sf_vec.contains(&t_sd) {
            new_vec.push(t_sd);
        }
    }

    // check removed subdomains 
    for s_sd in &sf_vec {
        if !tf_vec.contains(&s_sd) {
            rem_vec.push(s_sd)
        }
    }

    // print new subdomains, if there are any
    if new_vec.len() > 0 {
        println!("{}", format!("These new subdomains has been found - ").green());
        
        for (i, n_sub) in new_vec.iter().enumerate() {
            println!("{} -- {}", i+1, n_sub);
        }
    } else {
        println!("{}", format!("No new subdomains found!").bold());
    }

    // print removed subdomains, if there are any
    if rem_vec.len() > 0 {
        println!("{}", format!("These new subdomains seems to be removed - ").red());

        for (i, r_sub) in rem_vec.iter().enumerate() {
            println!("{} -- {}", i+1, r_sub);
        }
    } else {
        println!("{}", format!("No removed subdomains found!").bold());
    }

    // remove the existing savefile
    fs::remove_file(sf_file).unwrap();

    // rename tempfile to savefile
    fs::rename(tf_file, env::home_dir().unwrap().join(".certdiff").join(&target).join("savefile")).unwrap();

}
