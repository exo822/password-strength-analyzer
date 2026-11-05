# Password Strength Analyzer

A Python command-line tool for analyzing sample passwords
and generating secure random passwords.

## Features

- Estimates strength based on password length and predictable patterns
- Detects common passwords and simple substitutions
- Identifies repeated characters, repeated blocks, and sequences
- Provides suggestions for improving passwords
- Generates passwords between 16 and 128 characters using Python's secrets module
- Runs locally without saving passwords or making network requests

## How to Run

Requires Python 3. No additional packages are needed.

1. Download or clone this repository.
2. Open a terminal in the project folder.
3. Run:

   python password_analyzer.py

4. Choose an option:
   - 1: Analyze a sample password
   - 2: Generate a password
   - 3: Exit

## Limitations

Strength ratings are based on basic rules and do not guarantee
password security. The tool does not check breached-password
databases or personal information.

Password input is visible in the console. Use sample passwords
when testing or demonstrating the project.

## Technologies

- Python
- secrets
- string
