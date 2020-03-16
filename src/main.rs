extern crate clap;

use clap::{Arg, App};

use std::env::var;
use std::fs;


fn main() {

    // clap thang
    let arg_matches = App::new("facediff")
        .version("0.0.1")
        .author("Sahil Tembhare @isrsahilmk")
        .about("Facebook cert diffing tool for continuous subdomain reconnaissance, single use as well. (This tool will save all the data into ~/.facediff directory")
        .arg(Arg::with_name("target")
            .short("t")
            .long("target")
            .value_name("target domain")
            .help("Enter the target site, you can keep track of subdomains of the target site")
            .takes_value(true))
        .arg(Arg::with_name("facebook_api_token")
            .short("a")
            .long("api")
            .value_name("facebook api token")
            .help("Enter your facebook API token which will be used to access the facebook cert transparency tool")
            .takes_value(true)).get_matches();

    // checking if ~/.facediff dir exists, if not, create one            
    match fs::create_dir(format!("{}/.facediff", var("HOME").unwrap().to_string())) {
        Ok(_) => (),
        Err(_) => ()
    }

    // save the api token
    match arg_matches.value_of("facebook_api_token") {
        Some(api_key) => {
            match fs::write(format!("{}/.facediff/.apikey", var("HOME").unwrap().to_string()), api_key) {
                Ok(()) => println!("Api key saved succesfully."),
                Err(_) => ()
            }
        },
        None => ()
    }

    // call the client
    match arg_matches.value_of("target") {
        Some(target) => {
            match client(&target.to_string()) {
                Ok(()) => (),
                Err(_) => ()
            }
        },
        None => println!("Target arg not passed, see help using --help")
    }
}

fn client(target: &String) -> Result<(), Box<dyn std::error::Error>> {

    let apikey = fs::read_to_string(format!("{}/.facediff/.apikey", var("HOME")?.to_string())).expect("Unable to read the apikey");

    let response = reqwest::blocking::get(target)?.text_with_charset("utf-8")?;
    println!("Response: {}", &response);
    return Ok(());
}
