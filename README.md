# certdiff

This tool uses the cert transparency tool provided by sslmate, this tool will diff the subdomain scans. You can do this in a timely manner, can be used to do continuous subdomain recon. Gives detailed about new subdomains and removed subdomains as well

You might encounter some bugs while running this tool on windows, this tool is still in development.
PR's and issues are always welcome

## Installation

`cargo build --release`


## Usage

`certdiff -t target.com`

A directory will be created at ~/.certdiff and all of your targets data will be further stored in this directory

## Todo

* Save new subdomains logs in a file (along with a timestamp)
* Save removed subdomains logs in a file (along with a timestamp)
