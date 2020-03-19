extern crate clap;
extern crate json;

use clap::{Arg, App};

use std::env;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::{thread, time};

fn main() {

    // clap thang
    let arg_matches = App::new("certdiff")
        .version("0.0.1")
        .author("Sahil Tembhare @isrsahilmk")
        .about("sslmate cert diffing tool for continuous subdomain reconnaissance, single use as well. (This tool will save all the data into ~/.certdiff directory")
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
	 None => eprintln!("No home dir")
    }


    // call the http client
    match arg_matches.value_of("target") {
        Some(target) => {
            match http_client(&target.to_string()) {
                Ok(()) => (),
                Err(_) => ()
            }
        },
        None => eprintln!("[+] Target arg not passed, see help using --help [+]")
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
        eprintln!("[*] It seems that you have been rate limited on cert spotter api, try again later [*]");
    }
    
    return Ok(());
}

fn save_subs(target: &str, parsed_json: json::JsonValue) {

    match env::home_dir() {
        Some(home_path) => {
            match fs::create_dir(home_path.join(".certdiff").join(target)) {
                Ok(_) => {
                    println!("Directory created for {} at {} \n", target, home_path.join(".certdiff").join(target).display());
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
                        "\n[*] The subdomains has been saved into {}. Run another scan maybe after a week to check if they have new subdomains added, or removed. [*]"
                            , home_path.join(".certdiff").join(target).join("savefile").display()
                        );
                },

                Err(_) => {
                    // Err(_) means the savefile exists, now create one more for diffing -> tempfile
                    println!("[+] Directory for {} already exists [+]\n", target);
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
                        "\nNow diffing these subdomains with the previous scan to check for new subdomains or removed subdomains"
                    );
                    thread::sleep(time::Duration::from_secs(3));
                }
            }
        },
        None => eprintln!("No home dir")
    }
}
