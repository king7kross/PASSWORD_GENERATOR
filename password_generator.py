import random
import re
import string
import math

def get_character_set(include_uppercase, include_lowercase, include_digits, include_special):
    char_set = ""
    if include_uppercase:
        char_set += string.ascii_uppercase
    if include_lowercase:
        char_set += string.ascii_lowercase
    if include_digits:
        char_set += string.digits
    if include_special:
        special_chars = string.punctuation
        for ch in '()[]{}':
            special_chars = special_chars.replace(ch, '')
        char_set += special_chars
    return char_set

def validate_password(password, include_uppercase, include_lowercase, include_digits, include_special):
    if include_uppercase and not re.search(r'[A-Z]', password):
        return False
    if include_lowercase and not re.search(r'[a-z]', password):
        return False
    if include_digits and not re.search(r'[0-9]', password):
        return False
    if include_special and not re.search(r'[!\"#$%&\'*+,-./:;<=>?@\\\^_`|~]', password):
        return False
    return True

def generate_password(length, include_uppercase=True, include_lowercase=True, include_digits=True, include_special=True):

    if length < 1:
        raise ValueError("Password length must be at least 1")

    char_set = get_character_set(include_uppercase, include_lowercase, include_digits, include_special)
    if not char_set:
        raise ValueError("At least one character set must be selected")

    while True:
        password = ''.join(random.choice(char_set) for _ in range(length))
        if validate_password(password, include_uppercase, include_lowercase, include_digits, include_special):
            return password

def calculate_entropy(password_length, char_set_size):
    if char_set_size == 0 or password_length == 0:
        return 0
    entropy = password_length * math.log2(char_set_size)
    return entropy

def get_strength_description(entropy):
    if entropy < 28:
        return "Very Weak"
    elif entropy < 36:
        return "Weak"
    elif entropy < 60:
        return "Reasonable"
    elif entropy < 128:
        return "Strong"
    else:
        return "Very Strong"

def estimate_time_to_break(entropy):
    # Attack speeds in guesses per second for different attack types
    attack_speeds = {
        "Online attack (100 guesses/second)": 100,
        "Offline slow hash (10,000 guesses/second)": 10_000,
        "Offline fast hash (1 billion guesses/second)": 1_000_000_000,
        "Massive GPU cluster (100 billion guesses/second)": 100_000_000_000,
    }
    time_estimates = {}
    total_possibilities = 2 ** entropy
    for attack, speed in attack_speeds.items():
        seconds = total_possibilities / speed
        time_estimates[attack] = seconds
    return time_estimates

def format_time(seconds):
    intervals = (
        ('years', 31536000),
        ('days', 86400),
        ('hours', 3600),
        ('minutes', 60),
        ('seconds', 1),
    )
    result = []
    for name, count in intervals:
        value = int(seconds // count)
        if value > 0:
            seconds -= value * count
            result.append(f"{value} {name}")
    if not result:
        return "less than 1 second"
    return ', '.join(result)

def main():
    print("Secure Password Generator")
    try:
        length = int(input("Enter desired password length: "))
    except ValueError:
        print("Invalid input. Please enter a valid integer for length.")
        return

    print("Select character sets to include in the password:")
    include_uppercase = input("Include uppercase letters? (y/n): ").strip().lower() == 'y'
    include_lowercase = input("Include lowercase letters? (y/n): ").strip().lower() == 'y'
    include_digits = input("Include digits? (y/n): ").strip().lower() == 'y'
    include_special = input("Include special characters? (y/n): ").strip().lower() == 'y'

    try:
        password = generate_password(length, include_uppercase, include_lowercase, include_digits, include_special)
        print("\nGenerated Password:", password)

        # Calculate entropy and strength
        char_set = get_character_set(include_uppercase, include_lowercase, include_digits, include_special)
        entropy = calculate_entropy(length, len(char_set))
        strength = get_strength_description(entropy)
        print(f"Password Strength: {strength} (Entropy: {entropy:.2f} bits)")

        # Estimate time to break
        time_estimates = estimate_time_to_break(entropy)
        print("Estimated time to break the password:")
        for attack, seconds in time_estimates.items():
            print(f"  {attack}: {format_time(seconds)}")

    except ValueError as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
