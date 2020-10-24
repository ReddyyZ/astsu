# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v1.0] - 2020-05-22
### Added
### Arguments
-sC | Scan common ports
-sA | Scan all ports
- -sO | Scan OS
  - -i | Interface to use in the scan
-sP | Scan defined port
- -d | Discover hosts in the network
  - -p | Protocol to use in the scan
  - -i | Interface to use in the scan

## [v1.1] - 2020-05-24
### Added
Improved port scans, now using scapy, and having 3 scan methods, TCP Connect, TCP Stealth, and UDP.
### Modified
I modified the entire script, leaving the functions in a class, better structuring the project, being possible until it was imported and used by another script.
## Arguments
- -sC | Scan common ports
  - -p | Protocol to use in the scan
  - -i | Interface to use
  - -t | Timeout to each request
  - -st | Use stealth scan method (TCP)
- -sA | Scan all ports
  - -p  | Protocol to use in the scan
  - -i  | Interface to use
  - -t  | Timeout to each request
  - -st | Use stealth scan method (TCP)
- -sP | Scan a range ports
  - -p | Protocol to use in the scan
  - -i | Interface to use
  - -t | Timeout to each request
  - -st | Use stealth scan method (TCP)
- -sO | Scan OS of a target
- -d | Discover hosts in the network
  - -p | Protocol to use in the scan
  - -i | Interface to use

## [v1.1.1] - 2020-10-21
### Added
- Bug fixes on "Discover Hosts" scan.

## [v1.1.2] - 2020-10-21

- Formatting results
- Added loading bar

## [v1.1.3] - 2020-10-24

- Formatting results
- Bug fixes
