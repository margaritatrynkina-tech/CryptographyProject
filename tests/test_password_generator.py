import pytest
from src.core.vault.password_generator import PasswordGenerator


class TestPasswordGenerator:
    def setup_method(self):
        self.gen = PasswordGenerator()

    def test_default_length(self):
        pwd = self.gen.generate()
        assert len(pwd) == 16

    def test_custom_length(self):
        for length in [8, 12, 20, 32, 64]:
            pwd = self.gen.generate(length=length)
            assert len(pwd) == length

    def test_contains_uppercase(self):
        pwd = self.gen.generate(uppercase=True, lowercase=False, digits=False, symbols=False)
        assert any(c.isupper() for c in pwd)
        assert not any(c.islower() for c in pwd)

    def test_contains_lowercase(self):
        pwd = self.gen.generate(uppercase=False, lowercase=True, digits=False, symbols=False)
        assert not any(c.isupper() for c in pwd)
        assert any(c.islower() for c in pwd)

    def test_contains_digits(self):
        pwd = self.gen.generate(uppercase=False, lowercase=False, digits=True, symbols=False)
        assert any(c.isdigit() for c in pwd)

    def test_contains_symbols(self):
        pwd = self.gen.generate(uppercase=False, lowercase=False, digits=False, symbols=True)
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        assert any(c in symbols for c in pwd)

    def test_avoids_ambiguous_chars(self):
        pwd = self.gen.generate(length=100, avoid_ambiguous=True)
        ambiguous = "lI10O"
        for ch in ambiguous:
            assert ch not in pwd

    def test_no_duplicates_in_bulk(self):
        passwords = set()
        for _ in range(100):
            pwd = self.gen.generate()
            assert pwd not in passwords
            passwords.add(pwd)