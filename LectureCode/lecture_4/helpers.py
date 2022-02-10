import pefile 
from PIL import Image 


evil = pefile.PE("assets/evil.exe")
print(evil.get_imphash())

def make_ICO(f_name, f_new):
    im = Image.open(f_name)
    # optionally, you could set the icon sizes
    im.save(f"{f_new}.ico")

# to host the malware for testing, run the following in ./bin/
# python -m http.server 1234