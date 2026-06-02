import secrets
import time
from typing import Any, Union
import hmac
import hashlib


def constant_time_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')
    
    return secrets.compare_digest(a, b)


def secure_string_compare(a: str, b: str) -> bool:

    # Normalize strings to prevent encoding-based attacks
    a_norm = a.encode('utf-8').decode('utf-8', 'ignore')
    b_norm = b.encode('utf-8').decode('utf-8', 'ignore')
    
    return constant_time_compare(a_norm, b_norm)


def constant_time_select(condition: bool, true_value: Any, false_value: Any) -> Any:

    # Convert condition to integer (0 or 1)
    mask = -int(condition)
    
    # Use bitwise operations to select value
    return (true_value & mask) | (false_value & ~mask)


def secure_hmac_compare(key: bytes, data1: bytes, data2: bytes) -> bool:

    hmac1 = hmac.new(key, data1, hashlib.sha256).digest()
    hmac2 = hmac.new(key, data2, hashlib.sha256).digest()
    
    return constant_time_compare(hmac1, hmac2)


def timing_attack_resistant_operation(func):

    import random
    
    def wrapper(*args, **kwargs):
        # Execute the function
        result = func(*args, **kwargs)
        
        # Add random delay to obscure timing
        delay_ms = random.uniform(1.0, 5.0)  # 1-5 ms random delay
        time.sleep(delay_ms / 1000.0)
        
        return result
    
    return wrapper


class SecureBuffer:

    
    def __init__(self, data: bytes):

        self._data = bytearray(data)
        self._length = len(data)
    
    def compare(self, other: 'SecureBuffer') -> bool:

        if self._length != other._length:
            return False
        
        result = 0
        for i in range(self._length):
            result |= self._data[i] ^ other._data[i]
        
        return result == 0
    
    def clear(self):

        for i in range(self._length):
            self._data[i] = 0
        self._length = 0
    
    def __len__(self):
        return self._length
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()


# Test the module
if __name__ == "__main__":
    # Test constant_time_compare
    test1 = "password123"
    test2 = "password123"
    test3 = "password124"
    
    print(f"Test 1 == Test 2: {constant_time_compare(test1, test2)}")  # Should be True
    print(f"Test 1 == Test 3: {constant_time_compare(test1, test3)}")  # Should be False
    
    # Test SecureBuffer
    buf1 = SecureBuffer(b"secret data")
    buf2 = SecureBuffer(b"secret data")
    buf3 = SecureBuffer(b"different data")
    
    print(f"Buffer 1 == Buffer 2: {buf1.compare(buf2)}")  # Should be True
    print(f"Buffer 1 == Buffer 3: {buf1.compare(buf3)}")  # Should be False