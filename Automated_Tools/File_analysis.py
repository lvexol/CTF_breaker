import os
import hashlib
import magic
from PIL import Image
import zipfile
import io
from io import BytesIO
import struct

def get_file_type(filepath):
    mime = magic.Magic(mime=True)
    return mime.from_file(filepath)

def check_for_modifications(filepath):
    actual_type = get_file_type(filepath).split('/')[1]
    return actual_type

def calculate_hash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def extract_exif(filepath):
    try:
        image = Image.open(filepath)
        exif_data = image._getexif()
        if exif_data:
            return "\n".join([f"{tag}: {value}" for tag, value in exif_data.items()])
        else:
            return "No EXIF data found."
    except Exception:
        return "File is not an image or does not contain EXIF data."

def check_for_hidden_data(filepath):
    try:
        with open(filepath, 'rb') as file:
            data = file.read()
            if b'\x89PNG\r\n\x1a\n' in data:  # Check if PNG header exists
                return "Potential hidden data in PNG file."
            else:
                return "No hidden data detected."
    except Exception as e:
        return f"Error checking for hidden data: {e}"

def check_compression(filepath):
    try:
        with open(filepath, 'rb') as file:
            header = file.read(4)
            if header == b'PK\x03\x04':  # ZIP file magic bytes
                return "File is a ZIP archive."
            else:
                return "File is not a ZIP archive."
    except Exception as e:
        return f"Error checking compression: {e}"

def compare_magic_bytes(filepath):
    magic_bytes = {
        'PDF': b'%PDF',
        'PNG': b'\x89PNG\r\n\x1a\n',
        'JPEG': b'\xFF\xD8\xFF'
    }
    try:
        with open(filepath, 'rb') as file:
            file_start = file.read(8)  # Read more bytes to accommodate longer signatures
            for file_type, signature in magic_bytes.items():
                if file_start.startswith(signature):
                    return f"File matches {file_type} signature."
            return "File signature does not match known types."
    except Exception as e:
        return f"Error checking file signature: {e}"

def analyze_file(filepath):
    print("\n" + "="*50)
    print(f"Analyzing file: {filepath}")
    print("="*50 + "\n")

    # File Type
    file_type = get_file_type(filepath)
    print(f"1. Detected File Type: {file_type}\n")

    # Modifications Check
    actual_type = check_for_modifications(filepath)
    print(f"2. File Type Check: {actual_type}\n")

    # Hash Calculation
    hash_value = calculate_hash(filepath)
    print(f"3. SHA-256 Hash: {hash_value}\n")

    # EXIF Data (Image Files)
    if file_type.startswith("image"):
        exif_data = extract_exif(filepath)
        print(f"4. EXIF Metadata:\n{exif_data}\n")

    # Hidden Data (Steganography)
    hidden_data = check_for_hidden_data(filepath)
    print(f"5. Hidden Data Check: {hidden_data}\n")

    # Compression Check (ZIP files)
    compression_check = check_compression(filepath)
    print(f"6. Compression Check: {compression_check}\n")

    # Magic Bytes (File Signature Check)
    magic_check = compare_magic_bytes(filepath)
    print(f"7. Magic Bytes Check: {magic_check}\n")

    print("Analysis complete.\n")

def main():
    while True:
        print("\nFile Analysis Tool")
        print("-----------------")
        filepath = input("Enter the path to the file to analyze (or 'q' to quit): ").strip()
        
        if filepath.lower() == 'q':
            print("Goodbye!")
            break
            
        if not os.path.exists(filepath):
            print("Error: File does not exist. Please check the path and try again.")
            continue
            
        try:
            analyze_file(filepath)
        except Exception as e:
            print(f"Error analyzing file: {e}")
            
        print("\nPress Enter to analyze another file, or 'q' to quit")
        if input().lower() == 'q':
            print("Goodbye!")
            break

if __name__ == "__main__":
    main()