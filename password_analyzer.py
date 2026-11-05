"""A local password analyzer and secure password generator."""

import secrets
import string


# A small example list, not a complete breached-password database.
COMMON_PASSWORDS = {
    "password",
    "password1",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "qwerty123",
    "abc123",
    "admin",
    "letmein",
    "welcome",
    "iloveyou",
}

SEQUENCES = (
    string.ascii_lowercase,
    string.digits,
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)


def has_sequence(password):
    """Detect sequences such as abcd, 4321, or qwer."""
    lowered = password.lower()

    for sequence in SEQUENCES:
        for index in range(len(sequence) - 3):
            chunk = sequence[index:index + 4]

            if chunk in lowered or chunk[::-1] in lowered:
                return True

    return False


def analyze_password(password):
    """Return an estimated strength rating, issues, and suggestions."""
    length = len(password)

    if not password:
        return {
            "rating": "Very weak",
            "length": 0,
            "issues": ["The password is empty."],
            "suggestions": ["Enter a password to analyze."],
        }

    issues = []
    suggestions = []

    # Longer passwords start with a higher score.
    if length < 8:
        score = 0
    elif length < 12:
        score = 1
    elif length < 16:
        score = 2
    elif length < 20:
        score = 3
    else:
        score = 4

    if length < 16:
        suggestions.append(
            "Aim for at least 16 characters, or use a long passphrase "
            "made from randomly chosen words."
        )

    lowered = password.lower()

    # Recognize some common character substitutions.
    substitutions = str.maketrans({
        "@": "a",
        "0": "o",
        "$": "s",
        "3": "e",
        "1": "i",
    })

    normalized = lowered.translate(substitutions)

    letters_only = "".join(
        character
        for character in normalized
        if character.isalpha()
    )

    common = (
        lowered in COMMON_PASSWORDS
        or letters_only in {
            "password",
            "qwerty",
            "admin",
            "letmein",
            "welcome",
        }
    )

    if common:
        issues.append(
            "Matches a common password or a simple variation."
        )
        suggestions.append(
            "Choose something unrelated to common passwords."
        )

    # Check for three identical characters in a row.
    repeated_characters = any(
        password[index] == password[index + 1] == password[index + 2]
        for index in range(length - 2)
    )

    if repeated_characters:
        issues.append(
            "Contains three or more identical characters in a row."
        )
        score -= 1

    if has_sequence(password):
        issues.append(
            "Contains a predictable keyboard, letter, or number sequence."
        )
        score -= 1

    if len(set(password)) <= 2:
        issues.append("Uses very few distinct characters.")
        score = min(score, 1)

    # Check for repeated blocks, such as Blue!Blue!Blue!Blue!
    repeated_block = any(
        length % size == 0
        and password == password[:size] * (length // size)
        for size in range(1, length // 2 + 1)
    )

    if repeated_block:
        issues.append(
            "Consists of a repeated block of characters."
        )
        score = min(score, 1)

    if password.isdigit():
        issues.append("Contains only numbers.")
        score = min(score, 1)

    if common:
        score = 0

    score = max(0, min(score, 4))

    ratings = [
        "Very weak",
        "Weak",
        "Fair",
        "Strong",
        "Very strong",
    ]

    suggestions.append("Use a unique password for every account.")
    suggestions.append("Store passwords in a password manager.")

    return {
        "rating": ratings[score],
        "length": length,
        "issues": issues,
        "suggestions": suggestions,
    }


def generate_password(length=20):
    """Generate a password using cryptographically secure randomness."""
    if not 16 <= length <= 128:
        raise ValueError("Choose a length between 16 and 128.")

    groups = (
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        "!@#$%^&*()-_=+",
    )

    alphabet = "".join(groups)

    while True:
        password = "".join(
            secrets.choice(alphabet)
            for _ in range(length)
        )

        # Require at least one character from each group.
        includes_all_groups = all(
            any(character in group for character in password)
            for group in groups
        )

        if includes_all_groups:
            return password


def display_analysis(result):
    """Print the analysis results."""
    print(f"\nEstimated strength: {result['rating']}")
    print(f"Length: {result['length']} characters")

    print("\nDetected issues:")

    if result["issues"]:
        for issue in result["issues"]:
            print(f"  - {issue}")
    else:
        print("  No obvious patterns detected.")

    print("\nSuggestions:")

    for suggestion in result["suggestions"]:
        print(f"  - {suggestion}")

    print(
        "\nThis is a basic estimate, not a security guarantee."
        "\nIt does not check breached-password databases."
    )


def main():
    """Display the menu and handle user choices."""
    print("PASSWORD ANALYZER")
    print("Runs locally without saving or sending passwords.")
    print("Input is visible. Use sample passwords while testing.")

    while True:
        print("\n1. Analyze a password")
        print("2. Generate a password")
        print("3. Exit")

        choice = input("Choose 1, 2, or 3: ").strip().lower()

        if choice in ("1", "analyze"):
            password = input("Enter a sample password: ")
            result = analyze_password(password)
            display_analysis(result)

        elif choice in ("2", "generate"):
            length_input = input(
                "Enter a length between 16 and 128 "
                "(press Enter for 20): "
            ).strip()

            try:
                length = int(length_input) if length_input else 20
                password = generate_password(length)
                print(f"\nGenerated password: {password}")
                print("Visible in this console; store it securely.")

            except ValueError:
                print(
                    "Please enter a whole number between 16 and 128."
                )

        elif choice in ("3", "exit", "quit"):
            print("Goodbye!")
            break

        else:
            print("Invalid option. Enter 1, 2, or 3.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nGoodbye!")