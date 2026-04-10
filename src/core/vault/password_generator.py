import secrets
import string
class PasswordGenerator:
    def __init__(self):
        self.ambiguous = set('lI10O')
    def generate(self, length: int = 16,
                 uppercase: bool = True,
                 lowercase: bool = True,
                 digits: bool = True,
                 symbols: bool = True) -> str:
        if length < 8:
            raise ValueError("Длина минимум 8")
        charset = []
        if uppercase:
            charset.append([c for c in string.ascii_uppercase if c not in self.ambiguous])
        if lowercase:
            charset.append([c for c in string.ascii_lowercase if c not in self.ambiguous])
        if digits:
            charset.append([c for c in string.digits if c not in self.ambiguous])
        if symbols:
            charset.append(list("!@#$%^&*()_+-=[]{}|;:,.<>?"))
        if not charset:
            raise ValueError("Нужен хотя бы один набор символов")
        password = []
        for char_set in charset:
            password.append(secrets.choice(char_set))
        all_chars = ''.join(''.join(char_set) for char_set in charset)  # ← ИСПРАВЛЕНО!
        password += [secrets.choice(all_chars) for _ in range(length - len(charset))]
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)