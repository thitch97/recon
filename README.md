`vet` is a tool that uses the [VirusTotal
API](https://developers.virustotal.com/v6.0/reference) to surface security
analysis data for a given file.

## Setup

### Authentication
- Sign up for a VirusTotal community account.

- Navigate to your profile and retrieve your API key.

- Run `$ export VIRUS_TOTAL_API_KEY=<your-api-key>` from your shell.

### Installation

- Clone this repo

- Run `$ go install`

## Usage

`vet --file <path-to-file>`




