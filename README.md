# Password Generator

A secure password generator written in Python. This tool creates strong, random passwords based on user-selected criteria and estimates their strength and resistance to various attack types.

## Features

- Customizable password length
- Option to include uppercase, lowercase, digits, and special characters
- Password strength estimation (entropy calculation)
- Time-to-break estimates for different attack scenarios

## Usage

Run the script in your terminal:

```sh
python password_generator.py
```

Follow the prompts to select password length and character sets.

## Example Output

```
Secure Password Generator
Enter desired password length: 16
Select character sets to include in the password:
Include uppercase letters? (y/n): y
Include lowercase letters? (y/n): y
Include digits? (y/n): y
Include special characters? (y/n): y

Generated Password: aB3$dE!fGh7@LmNp
Password Strength: Strong (Entropy: 104.00 bits)
Estimated time to break the password:
  Online attack (100 guesses/second): 6,427,752,921,000 years
  Offline slow hash (10,000 guesses/second): 64,277,529,210 years
  Offline fast hash (1 billion guesses/second): 642,775 years
  Massive GPU cluster (100 billion guesses/second): 6 years
```

## Requirements

- Python 3.6 or higher
