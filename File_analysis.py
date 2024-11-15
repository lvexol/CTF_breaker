import os
import hashlib
import magic
from tkinter import Tk, filedialog, Label, Text, Scrollbar, END
from PIL import Image
import PyPDF2
import zipfile
import io
from io import BytesIO
import struct

# Function to get file type
def get_file_type(filepath):
    mime = magic.Magic(mime=True)
    return mime.from_file(filepath)

# Function to check if file type was modified
def check_for_modifications(filepath):
    actual_type = get_file_type(filepath).split('/')[1]
    return actual_type

# Function to calculate file hash
def calculate_hash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Function to extract EXIF metadata from images
def extract_exif(filepath):
    try:
        image = Image.open(filepath)
        exif_data = image._getexif()
        if exif_data:
            return "\n".join([f"{tag}: {value}" for tag, value in exif_data.items()])
        else:
            return "No EXIF data found."
    except IOError:
        return "File is not an image or does not contain EXIF data."

# Function to extract text from PDF files
def extract_pdf_text(filepath):
    try:
        with open(filepath, 'rb') as pdf_file:
            pdf_reader = PyPDF2.PdfReader(pdf_file)
            text = ""
            for page in pdf_reader.pages:
                text += page.extract_text() + "\n"
            return text[:500]  # Display first 500 chars
    except Exception as e:
        return f"Error reading PDF: {e}"

# Function to check for hidden data (basic steganography check for images)
def check_for_hidden_data(filepath):
    try:
        with open(filepath, 'rb') as file:
            data = file.read()
            if b'\x89PNG\r\n\x1a\n' in data:  # Check if PNG header exists (as an example)
                return "Potential hidden data in PNG file."
            else:
                return "No hidden data detected."
    except Exception as e:
        return f"Error checking for hidden data: {e}"

# Function to detect compressed files (e.g., ZIP)
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

# Function to compare file signatures (magic bytes)
def compare_magic_bytes(filepath):
    magic_bytes = {
        'PDF': b'%PDF',
        'PNG': b'\x89PNG\r\n\x1a\n',
        'JPEG': b'\xFF\xD8\xFF'
    }
    try:
        with open(filepath, 'rb') as file:
            file_start = file.read(4)
            for file_type, signature in magic_bytes.items():
                if file_start.startswith(signature):
                    return f"File matches {file_type} signature."
            return "File signature does not match known types."
    except Exception as e:
        return f"Error checking file signature: {e}"

# Main function to perform all analyses
def analyze_file():
    filepath = filedialog.askopenfilename()
    if not filepath:
        result_display.insert(END, "No file selected.\n")
        return

    result_display.delete(1.0, END)
    result_display.insert(END, f"Analyzing {filepath}...\n\n")

    # File Type
    file_type = get_file_type(filepath)
    result_display.insert(END, f"1. Detected File Type: {file_type}\n\n")

    # Modifications Check
    actual_type = check_for_modifications(filepath)
    result_display.insert(END, f"2. File Type Check: {actual_type}\n\n")

    # Hash Calculation
    hash_value = calculate_hash(filepath)
    result_display.insert(END, f"3. SHA-256 Hash: {hash_value}\n\n")

    # EXIF Data (Image Files)
    if file_type.startswith("image"):
        exif_data = extract_exif(filepath)
        result_display.insert(END, f"4. EXIF Metadata:\n{exif_data}\n\n")

    # PDF Text Extraction
    elif file_type == "application/pdf":
        pdf_text = extract_pdf_text(filepath)
        result_display.insert(END, f"5. PDF Text Content:\n{pdf_text}\n\n")

    # Hidden Data (Steganography)
    hidden_data = check_for_hidden_data(filepath)
    result_display.insert(END, f"6. Hidden Data Check: {hidden_data}\n\n")

<<<<<<< HEAD
    # Compression Check (ZIP files)
    compression_check = check_compression(filepath)
    result_display.insert(END, f"7. Compression Check: {compression_check}\n\n")

    # Magic Bytes (File Signature Check)
    magic_check = compare_magic_bytes(filepath)
    result_display.insert(END, f"8. Magic Bytes Check: {magic_check}\n\n")

    result_display.insert(END, "Analysis complete.\n")

# Setup the main window
root = Tk()
root.title("File Analysis Tool")

# File selection and analysis button
Label(root, text="Click 'Analyze' to select and analyze a file").pack(pady=10)
analyze_button = Label(root, text="Analyze", font=("Arial", 12), fg="blue", cursor="hand2")
analyze_button.pack(pady=5)
analyze_button.bind("<Button-1>", lambda event: analyze_file())

# Text box for displaying results
result_display = Text(root, wrap="word", width=80, height=25)
result_display.pack(padx=10, pady=10)

# Scrollbar
scroll = Scrollbar(root, command=result_display.yview)
scroll.pack(side="right", fill="y")
result_display.config(yscrollcommand=scroll.set)

root.mainloop()
=======
if __name__ == "__main__":
    main()
>>>>>>> refs/remotes/origin/main
