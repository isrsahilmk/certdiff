extern crate clap;

use clap::{Arg, App};

use std::env;

fn main() {

    // clap thang
    let arg_matches = App::new("facediff")
        .version("0.0.1")
        .author("Sahil Tembhare @isrsahilmk")
        .about("Facebook cert diffing tool for continuous subdomain reconnaissance, can also be used for single use. (This tool will save all the data into ~/.facediff directory")
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

    let target = arg_matches.value_of("target");

    match target {
        Some(target) => {
            client(&target.to_string());
        },
        None => println!("Target arg not passed, see help using --help")
    }
}

fn client(target: &String) -> Result<(), Box<dyn std::error::Error>> {

    let response = reqwest::blocking::get(target)?.text_with_charset("utf-8")?;
    println!("Response: {}", &response);
    return Ok(());
}
