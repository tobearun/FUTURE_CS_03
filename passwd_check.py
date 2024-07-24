import re


def check_password_strength(password):
    length_criteria = len(password) >= 12
    uppercase_criteria = re.search(r'[A-Z]', password) is not None
    lowercase_criteria = re.search(r'[a-z]', password) is not None
    number_criteria = re.search(r'[0,9]', password) is not None
    special_criteria = re.search(r'[\W]', password) is not None

    criteria_met = sum([length_criteria, uppercase_criteria, lowercase_criteria, number_criteria, special_criteria])

    return criteria_met, length_criteria, uppercase_criteria, lowercase_criteria, number_criteria, special_criteria


def evaluate_password_strength(password):
    criteria_met, length, upper, lower, number, special = check_password_strength(password)
    strength = {
        5: 'Very Strong',
        4: 'Strong',
        3: 'Modrate',
        2: 'Weak',
        1: 'Very Weak',
        0: 'Invalid'
    }
    return strength[criteria_met]


def load_common_password(filepath):
    with open(filepath, 'r', encoding='utf=8', errors='ignore') as file:
        return {line.strip().lower() for line in file}


common_passwords = load_common_password('rockyou.txt')


def detect_dictionary_attack(password):
    return password.lower() in common_passwords


def detect_bruteforce_attack(password):
    charset_size = 95
    bruteforce_time = charset_size ** len(password)
    return bruteforce_time


def analyze_vulnerabilities(password):
    dictionary_attack = detect_dictionary_attack(password)
    bruteforce_time = detect_bruteforce_attack(password)
    return dictionary_attack, bruteforce_time


def generate_report(password):
    strength = evaluate_password_strength(password)
    dictionary_attack, bruteforce_time = analyze_vulnerabilities(password)

    report = {
        'password': password,
        'strength': strength,
        'dictionary_attack': dictionary_attack,
        'bruteforce_time': bruteforce_time,
        'recommendation': []
    }

    if strength in ['Weak', 'Very Weak']:
        report['recommendation'].append(
            "Use a longer password with a mix of uppercase, lowercase, numbers, and special characters.")

    if dictionary_attack:
        report['recommendation'].append("Avoid using common passwords or dictionary words.")

    return report

if __name__ == "__main__":
    password = input("Enter a password to analyze: ")
    report = generate_report(password)

    print(f"Password Analysis Report for '{password}':")
    print(f"Strength: {report['strength']}")
    print(f"Vulnerable to Dictionary Attack: {'Yes' if report['dictionary_attack'] else 'No'}")
    print(f"Estimated Time to Brute-Force: {report['bruteforce_time']} attempts")
    print("Recommendations:")
    for recommendation in report['recommendation']:
        print(f" - {recommendation}")
