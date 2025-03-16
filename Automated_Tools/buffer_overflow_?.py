import re
import sys
from typing import List, Tuple, Dict

class BufferOverflowDetector:
    def __init__(self):
        # Common dangerous functions that can cause buffer overflows
        self.dangerous_functions = {
            'strcpy': 2,
            'strcat': 2,
            'gets': 1,
            'sprintf': -1,  # Variable arguments
            'scanf': -1,    # Variable arguments
            'memcpy': 3,
            'strncpy': 3,
            'strncat': 3,
        }
        
        # Patterns to detect buffer declarations
        self.buffer_patterns = [
            r'char\s+(\w+)\s*\[(\d+)\]',  # char buffer[size]
            r'wchar_t\s+(\w+)\s*\[(\d+)\]',  # wchar_t buffer[size]
            r'unsigned\s+char\s+(\w+)\s*\[(\d+)\]',  # unsigned char buffer[size]
        ]
        
    def find_buffer_declarations(self, code: str) -> Dict[str, int]:
        """Find all buffer declarations and their sizes."""
        buffers = {}
        
        for pattern in self.buffer_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                buffer_name = match.group(1)
                buffer_size = int(match.group(2))
                buffers[buffer_name] = buffer_size
                
        return buffers
    
    def find_dangerous_function_calls(self, code: str) -> List[Tuple[str, int, str]]:
        """Find all potentially dangerous function calls."""
        vulnerabilities = []
        
        # Find all function calls that might cause buffer overflows
        for func_name in self.dangerous_functions:
            # Pattern to match function calls with their arguments
            pattern = fr'\b{func_name}\s*\((.*?)\)'
            matches = re.finditer(pattern, code)
            
            for match in matches:
                line_num = len(code[:match.start()].split('\n'))
                args = match.group(1).split(',')
                vulnerabilities.append((func_name, line_num, match.group(0)))
                
        return vulnerabilities
    
    def analyze_string_literals(self, code: str, buffers: Dict[str, int]) -> List[Tuple[int, str]]:
        """Find string literals that might overflow declared buffers."""
        vulnerabilities = []
        
        # Find string assignments to buffers
        for buffer_name, size in buffers.items():
            # Pattern to match string assignments
            pattern = fr'{buffer_name}\s*=\s*"([^"]*)"'
            matches = re.finditer(pattern, code)
            
            for match in matches:
                string_content = match.group(1)
                if len(string_content) + 1 > size:  # +1 for null terminator
                    line_num = len(code[:match.start()].split('\n'))
                    vulnerabilities.append((line_num, 
                        f"Potential buffer overflow: String literal of size {len(string_content) + 1} "
                        f"exceeds buffer size {size}"))
                    
        return vulnerabilities

    def analyze_file(self, filename: str) -> List[str]:
        """Analyze a C/C++ source file for potential buffer overflows."""
        try:
            with open(filename, 'r') as f:
                code = f.read()
        except Exception as e:
            return [f"Error reading file: {str(e)}"]

        warnings = []
        
        # Find all buffer declarations
        buffers = self.find_buffer_declarations(code)
        
        # Check for dangerous function calls
        dangerous_calls = self.find_dangerous_function_calls(code)
        for func_name, line_num, call in dangerous_calls:
            warnings.append(f"Line {line_num}: Potentially dangerous function call: {call}")
            
        # Check string literals
        string_warnings = self.analyze_string_literals(code, buffers)
        for line_num, warning in string_warnings:
            warnings.append(f"Line {line_num}: {warning}")
            
        return warnings

def main():
    if len(sys.argv) != 2:
        print("Usage: python buffer_overflow_detector.py <source_file>")
        sys.exit(1)
        
    detector = BufferOverflowDetector()
    warnings = detector.analyze_file(sys.argv[1])
    
    if warnings:
        print("\nPotential buffer overflow vulnerabilities found:")
        for warning in warnings:
            print(f"- {warning}")
    else:
        print("\nNo obvious buffer overflow vulnerabilities detected.")
        print("Note: This is a basic static analysis and may not catch all vulnerabilities.")

if __name__ == "__main__":
    main()