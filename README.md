# Content Security Policy (CSP) Generator

## Overview

This Python script is designed to generate a Content Security Policy (CSP) for a given URL. It scans the URL, identifies all the JavaScript and CSS assets, computes their SHA-256 hashes, and creates a CSP policy. The policy helps in enhancing the security of web applications by specifying which resources are allowed to be loaded and executed.

## Features

- Added multithreading in v 1.1 so it runs much faster
- Fixed the malformed nonce creation for nonce policies
- Fetches and scans the provided URL for JavaScript and CSS assets.
- Computes SHA-256 hashes of the identified assets.
- Generates a CSP policy with or without a nonce.
- Displays tables of local and third-party assets along with their hashes.
- Provides warnings and examples on how to use nonces with inline scripts.

## Requirements

- Python 3.x
- `requests` library
- `beautifulsoup4` library
- `tabulate` library

## Installation and Running

You can install the required libraries using pip:

```sh
pip install -r requirements.txt

Run the script with:

```sh
python3 main.py
