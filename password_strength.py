import re

def check_password_strength(password):
    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    special_character_error = re.search(r"[ !@#$%^&*()_+{}\[\]:;<>,.?\/\\|`~-]", password) is None

    if length_error:
        return "Password is too short. It must be at least 8 characters long."
    elif digit_error:
        return "Password must contain at least one digit."
    elif uppercase_error:
        return "Password must contain at least one uppercase letter."
    elif lowercase_error:
        return "Password must contain at least one lowercase letter."
    elif special_character_error:
        return "Password must contain at least one special character."
    else:
        return "Password is strong."


if __name__ == "__main__":
    password = input("Enter your password: ")
    strength_feedback = check_password_strength(password)
    print(strength_feedback)