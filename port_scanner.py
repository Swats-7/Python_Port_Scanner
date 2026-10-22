import argparse
import socket 
import concurrent
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime 
import sys 
import csv

print("Welcome to port Scanner!")
socket.setdefaulttimeout(0.2)

COMMON_PORTS = {21: "FTP",22: "SSH",23: "Telnet",25: "SMTP",53: "DNS",80: "HTTP",110: "POP3",143: "IMAP",443: "HTTPS",3306: "MySQL",5432: "PostgreSQL",6379: "Redis",8080: "HTTP-alt"}
start_port = None 
end_port = None 

def Scan_udp(port) : 
    with socket.socket(socket.AF_INET , socket.SOCK_DGRAM) as s : 
        try : 
            s.sendto(b"Ping",(target,port))

            response = s.recvfrom(1024)

        except socket.timeout : 
            return {"Port": port, "Protocol": "udp", "State": "open|filtered"}

        except ConnectionRefusedError : 
            return {"Port": port, "Protocol": "udp", "State": "closed"}

        except : 
            return 0 

def Scan_tcp(port) : 
    with socket.socket(socket.AF_INET , socket.SOCK_STREAM) as s :  
        result = s.connect_ex((target,port))
        if result == 0 : 
            try : 
                banner = s.recv(1024).decode()
                return {"Port": port, "Protcol": "tcp", "State": "open", "Service": COMMON_PORTS.get(port, "unknown"), "Banner": {banner}}

            
            except : 
            
                return {"Port": port, "Protcol": "tcp", "State": "open", "Service": COMMON_PORTS.get(port, "unknown"), "Banner": ""}
        
        else : return 0 


parser = argparse.ArgumentParser()
parser.add_argument('-p' , '--ports' , type=int , nargs='*' , help="Ports to be scanned can be specified")
parser.add_argument('-t','--target',type=str, required=True, help="Specify the target IPv4 address")
parser.add_argument('-s','--scan',type=str, help="Specify the type of scan to commence : 1. full \n 2. common")
parser.add_argument('-n', '--numscans', type=int, help="Specify the number of simultaneous scans" )
parser.add_argument('-u', '--udp', action="store_true", help="Used to scan UDP ports instead of TCP")
parser.add_argument('-f', '--file', type=str, help="Specify the file to store the output of the scan")
args = parser.parse_args()

target = args.target

if args.scan is not None and args.scan == "full" : 
    start_port = 0 
    end_port = 65535 

elif args.scan is not None and args.scan == "common" : 
    args.ports = list(COMMON_PORTS.keys())

if args.scan is not None and args.ports is not None : 
    print("cannot specify scan type and ports simultaneously.")
    sys.exit(0)

if args.numscans is None : 
    args.numscans = 5

#udp scan when ports are specified in the cli 
if args.ports is not None and max(args.ports) <= 65535 and min(args.ports) > 0 and args.udp : 
    socket.setdefaulttimeout(1)
    start_time = datetime.now()

    #opening the csv file in write mode 
    if (args.file != None and args.file != "") :
        with open(args.file, 'w') as f :
            writer = csv.writer(f)
            writer.writerow(['Port', 'Protocol', 'State'])

    print(f"Scan started at time {start_time}")
    print("-"*50)
    with ThreadPoolExecutor(max_workers=args.numscans) as executor : 
        futures = {executor.submit(Scan_udp,port) : port for port in args.ports}

        for future in concurrent.futures.as_completed(futures) : 
            l = []
            port = futures[future]
            result = future.result() 
            if result != 0 : 
                for v in result.values() : 
                    l.append(v)
                    print(v, end=" ")
                if args.file != None and str(args.file) != "" : 
                    with open(str(args.file), "a") as f : 
                        writer = csv.writer(f) 
                        writer.writerow(l)
                print()

    end_time = datetime.now()
    print(f"Scan completed in : {end_time - start_time}")
    sys.exit(0)

#Scan if ports are specified by the user using the cli 
if args.ports is not None and max(args.ports) <= 65535 and min(args.ports) > 0 and args.udp == False : 
    start_time = datetime.now()

    #opening the csv file in write mode 
    if (args.file != None and str(args.file) != "") :
        with open(str(args.file), 'w') as f :
            writer = csv.writer(args.file)
            writer.writerow(['Port', 'Protocol', 'State'])

    print(f"Scan started at time {start_time}")
    print("-"*50)
    with ThreadPoolExecutor(max_workers=args.numscans) as executor : 
        futures = {executor.submit(Scan_tcp,port) : port for port in args.ports} 

        for future in concurrent.futures.as_completed(futures) : 
            l = []
            port = futures[future]
            result = future.result()
            if result !=0 : 
                for v in result.values() : 
                    l.append(v)
                    print(v, end = " ")
                if args.file != None and str(args.file) != "" : 
                    with open(str(args.file), "a") as f : 
                        writer = csv.writer(f) 
                        writer.writerow(l)
                print()


    end_time = datetime.now()
    print(f"Scan completed in : {end_time - start_time}")
    sys.exit(0)

elif start_port == None and end_port == None : 
    start_port = int(input("Which port to start scanning from : "))
    end_port = int(input("Till which port to scan : "))

    if args.numscans is None : 
        args.numscans = 100


    if start_port < 0 or end_port > 65535: 
        sys.exit("Input invalid")

if args.ports is None and args.udp: 
    socket.setdefaulttimeout(1)

    #opening the csv file in write mode 
    if (args.file != None and str(args.file) != "") :
        with open(str(args.file), 'w') as f :
            writer = csv.writer(f)
            writer.writerow(['Port', 'Protocol', 'State'])

    num_ports = 0 
    total_ports = end_port-start_port
    start_time = datetime.now()
    print(f"Scan started at time {start_time}")
    print("-"*50)

    with ThreadPoolExecutor(max_workers= args.numscans) as executor : 
        futures = {executor.submit(Scan_udp,port) : port for port in range(start_port,end_port)}
        
        for future in concurrent.futures.as_completed(futures) :
            l = []
            num_ports += 1 
            port = futures[future] 
            result = future.result()
            if num_ports%1000 == 0 : 
                print(f"{num_ports} out of {total_ports} scanned") 

            if result != 0 : 
                for v in result.values() :
                    l.append(v) 
                    print(v,end = " ")
                if args.file != None and str(args.file) != "" : 
                    with open(str(args.file), "a") as f : 
                        writer = csv.writer(f) 
                        writer.writerow(l)
                print()


#Scan if ports arent specified in the cli by the user and are in the form of a range 
if args.ports is None and args.udp == False: 
    num_ports = 0 
    total_ports = end_port-start_port
    start_time = datetime.now()

    #opening the csv file in write mode 
    if (args.file != None and str(args.file) != "") :
        with open(str(args.file), 'w') as f :
            writer = csv.writer(f)
            writer.writerow(['Port', 'Protocol', 'State'])

    print(f"Scan started at time {start_time}")
    print("-"*50)

    with ThreadPoolExecutor(max_workers= args.numscans) as executor : 
        futures = {executor.submit(Scan_tcp,port) : port for port in range(start_port,end_port)}
        
        for future in concurrent.futures.as_completed(futures) :
            l = []
            num_ports += 1 
            port = futures[future] 
            result = future.result()
            if num_ports%1000 == 0 : 
                print(f"{num_ports} out of {total_ports} scanned") 

            if result != 0 : 
                for v in result.values() : 
                    l.append(v)
                    print(v,end = " ")
                if args.file != None and str(args.file) != "" : 
                    with open(str(args.file), "a") as f : 
                        writer = csv.writer(f) 
                        writer.writerow(l)
                print()


    end_time = datetime.now()
    print(f"Scan completed in : {end_time - start_time}")
    sys.exit(0)

    

