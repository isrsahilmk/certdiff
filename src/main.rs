fn main() -> Result<(), Box<dyn std::error::Error>> {
    let response = reqwest::blocking::get("https://google.com")?;
    println!("{:?}", response);

    return Ok(());
}
