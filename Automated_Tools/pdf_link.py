import PyPDF2
#if not installed PyPDF2 teh coment in terminal "pip install PyPDF2" then run the file again
import re

def find_urls(string):
    # Find all URLs using a regex pattern
    regex_url = r'https?://\S+'
    urls = re.findall(regex_url, string)
    return urls

# Open the PDF file using 'with' statement
# enter your pdf name and run it in the current directory
with open("newfile.pdf", 'rb') as file:
    # Create a PdfReader object
    read_pdf = PyPDF2.PdfReader(file)

    # Iterating over all the pages of the file
    for page_no in range(len(read_pdf.pages)):
        # Get the page object
        page = read_pdf.pages[page_no]

        # Extract text from the page
        text = page.extract_text()

        # Print all URLs on the page
        print(find_urls(text))
file.close()
# No need to explicitly close the file, as 'with' statement takes care of it