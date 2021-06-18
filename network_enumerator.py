#Host Discovery
#Port Scanning
#OS Detection
import nmap
scanner = nmap.PortScanner()


def host_discovery():
    print("initiating host discovery:\n\n\n")
    ip_addr = str(input("Enter ip address: "))
    print("you entered: ", ip_addr)
    try:
        scanner.scan(ip_addr)
        print("command executed: ", scanner.command_line())
        print("IP status: ", scanner[ip_addr].state())
    except:
        print("Host ",ip_addr, " is seemed to be blocked or down ")

    net_enum_start()


def port_scanning():
    print("initiating port scanning:\n\n\n")
    # ip_addr = "192.168.0.107"
    ip_addr = str(input("Enter ip address: "))
    print("you entered: ", ip_addr, "\n\n")
    # ip_port = "1-1024"
    ip_port = str(input("Enter port number: "))
    print("you entered: ", ip_port, "\n\n")
    scan_type = str(input("Scan type: 1)tcp or 2) udp : \n\n"))
    print("you entered: ", scan_type, "\n\n")

    if scan_type == 1:
        try:
            scanner.scan(ip_addr, ip_port, "-v -sS")
            print("command executed: ", scanner.command_line())
            print("IP status: ", scanner[ip_addr].state())
            open_ports = scanner[ip_addr]['tcp'].keys()
            for open_port in open_ports:
                print(open_port)
            # print(scanner.scaninfo())
        except:
            print("Host ",ip_addr, " is seemed to be blocked or down ")
    elif scan_type == 2:
        try:
            scanner.scan(ip_addr, ip_port, "-v -sU")
            print("command executed: ", scanner.command_line())
            print("IP status: ", scanner[ip_addr].state())
            open_ports = scanner[ip_addr]['udp'].keys()
            for open_port in open_ports:
                print(open_port)
            # print(scanner.scaninfo())
        except:
            print("Host ",ip_addr, " is seemed to be blocked or down ")
    else:
        print("invalid input...try again...\n\n")
        port_scanning()


def os_detection():
    print("initiating os detection:\n\n\n")
    ip_addr = "192.168.0.107"
    # ip_addr = str(input("Enter ip address: "))
    print("you entered: ", ip_addr, "\n\n")
    scanner = nmap.PortScanner()
    host = scanner.scan(ip_addr, arguments='-O')
    print(host['scan'][ip_addr]['osmatch'][0]['osclass'][0]['osfamily'])



def net_enum_start():
    print("Enter your choice of attack: ")
    print(""" \nPlease enter the type of scan you want to run
                    1Host Discovery
                    2)Port Scanning
                    3)OS Detection\n""")

    option_choice = int(input("your choice: "))

    if option_choice == 1:
        host_discovery()
    elif option_choice == 2:
        port_scanning()
    elif option_choice == 3:
        os_detection()
    else:
        print("invalid input")
        net_enum_start()