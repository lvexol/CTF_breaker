#!/usr/bin/env python3
import os
import hashlib
import magic  
from PIL import Image  
import PyPDF2 

def get_file_type(filepath):
    mime = magic.Magic(mime=True)
    file_type = mime.from_file(filepath)
    return file_type

def check_for_modifications(filepath):
    original_type = os.popen(f'file -b {filepath}').read().split()[0]
    actual_type = get_file_type(filepath).split('/')[1]
    if original_type != actual_type:
        print(f"Warning: File type mismatch! Original: {original_type}, Modified: {actual_type}")
    else:
        print("No modifications detected in file type.")

def calculate_hash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    print(f"SHA-256 Hash: {sha256_hash.hexdigest()}")

def extract_exif(filepath):
    try:
        image = Image.open(filepath)
        exif_data = image._getexif()
        if exif_data:
            print("EXIF Metadata:")
            for tag, value in exif_data.items():
                print(f"{tag}: {value}")
        else:
            print("No EXIF data found.")
    except IOError:
        print("File is not an image or does not contain EXIF data.")

def extract_pdf_text(filepath):
    try:
        with open(filepath, 'rb') as pdf_file:
            pdf_reader = PyPDF2.PdfReader(pdf_file)
            text = ""
            for page in pdf_reader.pages:
                text += page.extract_text() + "\n"
            print("PDF Text Content:\n", text[:500]) 
    except Exception as e:
        print("Error reading PDF:", e)

def main():
    filepath = input("Enter the file path for analysis: ")
    if not os.path.exists(filepath):
        print("File does not exist.")
        return

    print(f"\nAnalyzing {filepath}...\n")
    print("1. Detecting File Type:")
    file_type = get_file_type(filepath)
    print(f"Detected File Type: {file_type}\n")

    print("2. Checking for Modifications:")
    check_for_modifications(filepath)

    print("\n3. Calculating File Hash:")
    calculate_hash(filepath)

    if file_type.startswith("image"):
        print("\n4. Extracting EXIF Metadata:")
        extract_exif(filepath)
    elif file_type == "application/pdf":
        print("\n5. Extracting PDF Text Content:")
        extract_pdf_text(filepath)

    print("\nAnalysis complete.")

if _name_ == "_main_":
    main()