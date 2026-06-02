import ctypes
import sys
from typing import Any, Optional, Union
import warnings

_CtypesArray = Any  # ctypes.Array[c_ubyte] etc.


def _is_ctypes_array(buffer: Any) -> bool:
    return hasattr(buffer, "_type_") and hasattr(buffer, "_length_")


def _buffer_address_and_size(buffer: Any) -> tuple[int, int]:
    if _is_ctypes_array(buffer):
        return ctypes.addressof(buffer), len(buffer)
    if isinstance(buffer, bytearray):
        wrapper = (ctypes.c_char * len(buffer)).from_buffer(buffer)
        return ctypes.addressof(wrapper), len(buffer)
    if isinstance(buffer, memoryview):
        obj = buffer.obj
        if obj is not None and _is_ctypes_array(obj):
            return ctypes.addressof(obj), buffer.nbytes
        if isinstance(obj, bytearray):
            wrapper = (ctypes.c_char * buffer.nbytes).from_buffer(obj)
            return ctypes.addressof(wrapper), buffer.nbytes
    raise TypeError(f"Cannot securely zero buffer of type {type(buffer).__name__}")


def secure_zero(buffer: Union[bytearray, memoryview, _CtypesArray]) -> None:
    import ctypes as _ctypes

    if len(buffer) == 0:
        return
    addr, size = _buffer_address_and_size(buffer)
    ctypes.memset(addr, 0, size)


def copy_to_secure_buffer(buffer: _CtypesArray, data: bytes) -> None:
    if len(data) != len(buffer):
        raise ValueError("Data length does not match buffer size")
    if len(data) == 0:
        return
    ctypes.memmove(buffer, data, len(data))


class SecureMemory:
    
    def __init__(self):
        self._allocated = []
        self._platform = sys.platform
        
        # Check if we can lock memory
        self._can_lock = self._check_lock_support()
        
        if not self._can_lock:
            warnings.warn(
                "Memory locking not supported on this platform. "
                "Sensitive data may be swapped to disk.",
                RuntimeWarning
            )
    
    def _check_lock_support(self) -> bool:
        try:
            if self._platform == 'win32':
                # Check for VirtualLock
                kernel32 = ctypes.windll.kernel32
                return hasattr(kernel32, 'VirtualLock')
            else:
                # Check for mlock
                import ctypes.util
                libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
                return hasattr(libc, 'mlock')
        except:
            return False
    
    def allocate(self, size: int, lock: bool = True) -> _CtypesArray:
        if size <= 0:
            raise ValueError("Size must be positive")
        
        # Allocate aligned memory for better security
        # Use c_ubyte so slice assignment with bytes works correctly
        buffer_type = (ctypes.c_ubyte * size)
        buffer = buffer_type()

        # Get the memory address
        address = ctypes.addressof(buffer)
        
        # Lock memory if requested and supported
        if lock and self._can_lock:
            self._lock_memory(address, size)
        
        # Store reference to prevent garbage collection
        self._allocated.append((buffer, address, size, lock))
        
        return buffer
    
    def _lock_memory(self, address: int, size: int) -> None:
        if self._platform == 'win32':
            # Windows: VirtualLock
            kernel32 = ctypes.windll.kernel32
            if not kernel32.VirtualLock(address, size):
                error = ctypes.GetLastError()
                raise OSError(f"VirtualLock failed with error {error}")
        else:
            # POSIX: mlock
            import ctypes.util
            libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
            if libc.mlock(address, size) != 0:
                error = ctypes.get_errno()
                raise OSError(f"mlock failed with error {error}")
    
    def _unlock_memory(self, address: int, size: int) -> None:
        if self._platform == 'win32':
            # Windows: VirtualUnlock
            kernel32 = ctypes.windll.kernel32
            kernel32.VirtualUnlock(address, size)
        else:
            # POSIX: munlock
            import ctypes.util
            libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
            libc.munlock(address, size)
    
    def zero(self, buffer: _CtypesArray) -> None:
        for buf_obj, address, size, _locked in self._allocated:
            if buf_obj is buffer:
                ctypes.memset(address, 0, size)
                return
        secure_zero(buffer)

    def free(self, buffer: _CtypesArray) -> None:
        # Find the buffer in allocated list
        for i, (buf_obj, address, size, locked) in enumerate(self._allocated):
            if buf_obj is buffer:
                # Securely zero the memory
                self.zero(buffer)
                
                # Unlock memory if it was locked
                if locked and self._can_lock:
                    self._unlock_memory(address, size)
                
                # Remove from allocated list
                del self._allocated[i]
                break
        else:
            raise ValueError("Buffer not allocated by this SecureMemory instance")
    
    def clear_all(self) -> None:
        for buf_obj, address, size, locked in self._allocated:
            ctypes.memset(address, 0, size)
            
            # Unlock memory if it was locked
            if locked and self._can_lock:
                self._unlock_memory(address, size)
        
        self._allocated.clear()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear_all()
    
    def __del__(self):
        try:
            self.clear_all()
        except:
            pass  # Ignore errors during destruction


class SecureString:
    
    def __init__(self, string: str):
        self._mem = SecureMemory()
        encoded = string.encode('utf-8')
        self._buffer = self._mem.allocate(len(encoded))
        copy_to_secure_buffer(self._buffer, encoded)
        self._length = len(encoded)
    
    def compare(self, other: Union[str, 'SecureString']) -> bool:
        from .side_channel_protection import constant_time_compare
        
        if isinstance(other, SecureString):
            other_bytes = bytes(other._buffer)
        else:
            other_bytes = other.encode('utf-8')
        
        return constant_time_compare(bytes(self._buffer), other_bytes)
    
    def clear(self):
        if hasattr(self, '_buffer'):
            self._mem.zero(self._buffer)
            self._mem.free(self._buffer)
            self._buffer = None
            self._length = 0
    
    def __str__(self):
        return bytes(self._buffer).decode('utf-8') if self._buffer else ''
    
    def __len__(self):
        return self._length
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()
    
    def __del__(self):
        try:
            self.clear()
        except:
            pass


# Global secure memory allocator instance
_secure_mem = SecureMemory()


def allocate_secure(size: int, lock: bool = True) -> _CtypesArray:
    return _secure_mem.allocate(size, lock)


def free_secure(buffer: _CtypesArray) -> None:
    _secure_mem.free(buffer)


def clear_secure_memory() -> None:
    _secure_mem.clear_all()


# Test the module
if __name__ == "__main__":
    # Test secure_zero
    test_buffer = bytearray(b"secret data")
    print(f"Before zeroing: {test_buffer}")
    secure_zero(test_buffer)
    print(f"After zeroing: {test_buffer}")
    
    # Test SecureMemory
    with SecureMemory() as mem:
        buffer = mem.allocate(16)
        copy_to_secure_buffer(buffer, b"test data")
        print(f"Allocated buffer: {bytes(buffer)}")
        mem.zero(buffer)
        print(f"After zeroing: {bytes(buffer)}")
    
    # Test SecureString
    with SecureString("password123") as sstr:
        print(f"Secure string length: {len(sstr)}")
        print(f"Compare with same: {sstr.compare('password123')}")
        print(f"Compare with different: {sstr.compare('password124')}")