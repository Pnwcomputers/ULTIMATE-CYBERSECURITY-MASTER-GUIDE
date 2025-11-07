#!/usr/bin/env python3

"""
Simple File Format Fuzzer
WARNING: For educational purposes only. Use only in authorized testing environments.
"""

import random
import sys
import os

def fuzz(data):
    """Mutate input data by randomly modifying bytes"""
    fuzzed = bytearray(data)
    num_writes = random.randint(1, 10)
    
    for _ in range(num_writes):
        offset = random.randint(0, len(fuzzed) - 1)
        fuzzed[offset] = random.randint(0, 255)
    
    return bytes(fuzzed)

def main():
    if len(sys.argv) != 4:
        print("Usage: python file_fuzzer.py <template_file> <output_dir> <num_iterations>")
        sys.exit(1)
    
    template_file = sys.argv[1]
    output_dir = sys.argv[2]
    num_iterations = int(sys.argv[3])
    
    # Read template file
    try:
        with open(template_file, "rb") as f:
            original = f.read()
    except FileNotFoundError:
        print(f"[!] Template file not found: {template_file}")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate fuzzed files
    print(f"[+] Generating {num_iterations} fuzzed files...")
    for i in range(num_iterations):
        fuzzed_data = fuzz(original)
        
        # Get file extension from template
        ext = os.path.splitext(template_file)[1]
        filename = os.path.join(output_dir, f"fuzzed_{i}{ext}")
        
        with open(filename, "wb") as out:
            out.write(fuzzed_data)
        
        if (i + 1) % 10 == 0:
            print(f"[+] Generated {i + 1}/{num_iterations} files")
    
    print(f"[+] Fuzzing complete. Files saved to {output_dir}")

if __name__ == "__main__":
    main()
