import argparse
import zlib

class PNG:
    def __init__(self, input_file, output_file, verbose=False):
        self.input_file = input_file
        self.output_file = output_file
        self.verbose = verbose

    def log(self, message):
        if self.verbose:
            print(message)

    def check_and_repair_iend(self):
        # Standard IEND chunk structure
        standard_iend = b'\x00\x00\x00\x00IEND\xae\x42\x60\x82'
        
        # Read the input file data
        with open(self.input_file, 'rb') as file:
            data = file.read()
        
        # Locate the IEND chunk
        pos = data.find(b'IEND')
        
        # Check if IEND chunk is correct or missing
        if pos == -1 or data[pos-4:pos+8] != standard_iend:
            self.log("IEND chunk is missing or corrupt. Attempting repair...")
            # Repair: Add or replace with the standard IEND chunk
            data = data[:pos] + standard_iend if pos != -1 else data + standard_iend
            
            # Write the repaired data to the output file
            with open(self.output_file, 'wb') as file:
                file.write(data)
            print(f"Repaired file saved as {self.output_file}")
        else:
            self.log("PNG file is valid.")

    def decompress_zlib(self, zlib_file):
        with open(zlib_file, 'rb') as file:
            compressed_data = file.read()
        
        # Decompress using zlib
        try:
            decompressed_data = zlib.decompress(compressed_data)
            print("Decompressed data:")
            print(decompressed_data)
            return decompressed_data
        except zlib.error as e:
            print(f"Zlib decompression error: {e}")
            return None

if __name__ == '__main__':
    # Set up command-line arguments
    parser = argparse.ArgumentParser(description="PNG Check & Repair Tool with Verbose and Zlib Decompression")
    parser.add_argument('-i', '--input', required=True, help="Input PNG file")
    parser.add_argument('-o', '--output', default='output.png', help="Output file name (default: output.png)")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")
    parser.add_argument('-d', '--decompress', help="Decompress zlib data from specified file")
    args = parser.parse_args()

    # Instantiate the PNG checker
    png_checker = PNG(args.input, args.output, verbose=args.verbose)
    
    # Check and repair IEND chunk
    png_checker.check_and_repair_iend()
    
    # Decompress zlib data if provided
    if args.decompress:
        png_checker.decompress_zlib(args.decompress)
