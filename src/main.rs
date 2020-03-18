extern crate clap;
extern crate json;

use clap::{Arg, App};

use std::env;
use std::fs;
 

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
	 None => println!("No home dir")
    }


    // call the http client
    match arg_matches.value_of("target") {
        Some(target) => {
            match http_client(&target.to_string()) {
                Ok(()) => (),
                Err(_) => ()
            }
        },
        None => println!("Target arg not passed, see help using --help")
    }
}



fn http_client(target: &str) -> Result<(), Box<dyn std::error::Error>> {

    let url = format!("https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names", target);
    let response = reqwest::blocking::get(&url)?.text()?;

    // json parsing
    let parsed_json = json::parse(&response).unwrap();
   
    create_target_dir(&target, parsed_json);

    return Ok(());
}

fn create_target_dir(target: &str, parsed_json: json::JsonValue) {

    match env::home_dir() {
        Some(home_path) => {
            match fs::create_dir(home_path.join(".certdiff").join(target)) {
                Ok(_) => {
                    println!("Directory created for {}, at {} \n", target, home_path.join(".certdiff").join("target").display());
                    for data in parsed_json.members() {
                        for domain in data["dns_names"].members() {
                            println!("{}", domain);
                        }
                    }
                },
                Err(_) => {
                    // check if first file exists -> target(1), and create one more for diffing -> target(2)
                }
            }
        },
        None => println!("No home dir")
    }
}
