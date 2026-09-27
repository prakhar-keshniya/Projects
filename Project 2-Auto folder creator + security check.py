import os



image_extensions = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"]
document_extensions = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv"]

# Security_1
def Security_1(ext):
    if ext in image_extensions:
        print("This is an image file.")
    elif ext in document_extensions:
        print("This is an document file.")
    else:
        print("Unknown or unsupported file type.")

# Security_2
def Security_2(file):
    Double = file.split(".")

    if len(Double) >= 2:
        print("⚠ Suspicious file: Multiple extensions detected!")

# Security_3
def Security_3():
    if not os.path.exists(file):
        print("Folder already exists.")

#

file = input("Enter file name:- ")
ext = os.path.splitext(file)[1].lower()


# Security 1-Single extension check
Security_1(file)

# Security 2-Double extension check
Security_2(file)

# Security 3-File actually exist
Security_3(file)
