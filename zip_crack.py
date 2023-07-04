import zipfile
import os
from colored import fg, bg, attr

green = fg("green")
red = fg("red")

zip_name = input("[*] Zip: ")
password_file = input("[*] Password File: ")

if os.path.exists(zip_name):
    if os.path.exists(password_file):
        with open(password_file, 'rb') as text:
            for entry in text.readlines():
                password = entry.strip()

                with zipfile.ZipFile(zip_name, 'r') as zf:
                    try:
                        zf.extractall(pwd=password)
                        print(green + "\n[+] Password Found!\n" + attr("reset"))
                        data = zf.namelist()[0]
                        print("Data: " + str(data))
                        data_size = zf.getinfo(data).file_size
                        print("Data Size: " + str(data_size))
                        print("Password: " + password.decode("utf-8"))
                        break

                    except Exception as e:
                        print(red + "[-] Password Not Found! - " + password.decode("utf-8"), e)
                    pass

    else:
        print(red + "[-] Password File Not Found!")

else:
    print(red + "[-] Zip File Not Found!")


input()
