import re

COMMON_PASSWORDS = ["password", "password123", "qwerty", "123456", "admin"]


def validate_password_strength(password: str) -> str | None:
    if len(password) < 12:
        return "Пароль должен быть не менее 12 символов"

    if password.lower() in COMMON_PASSWORDS:
        return "Слишком простой/распространённый пароль"

    if not re.search(r"[A-Z]", password):
        return "Нужна хотя бы одна заглавная буква"
    if not re.search(r"[a-z]", password):
        return "Нужна хотя бы одна строчная буква"
    if not re.search(r"\d", password):
        return "Нужна хотя бы одна цифра"
    if not re.search(r"\W", password):
        return "Нужен хотя бы один спецсимвол"

    return None
