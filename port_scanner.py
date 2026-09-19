import argparse
import socket 
import concurrent
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime 
import sys 

socket.setdefaulttimeout(0.2)

COMMON_PORTS = {21: "FTP",22: "SSH",23: "Telnet",25: "SMTP",53: "DNS",80: "HTTP",110: "POP3",143: "IMAP",443: "HTTPS",3306: "MySQL",5432: "PostgreSQL",6379: "Redis",8080: "HTTP-alt"}
start_port = None 
end_port = None 

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
    
if args.ports is not None and max(args.ports) <= 65535 and min(args.ports) > 0: 
    start_time = datetime.now()
    print(f"Scan started at time {start_time}")
    with ThreadPoolExecutor(max_workers=args.numscans) as executor : 
        futures = {executor.submit(Scan_tcp,port) : port for port in args.ports} 

        for future in concurrent.futures.as_completed(futures) : 
            port = futures[future]
            result = future.result()
            if result !=0 : 
                for v in result.values() : 
                    print(v, end = " ")
                print()
    end_time = datetime.now()
    print(f"Scan completed in : {end_time - start_time}")

elif start_port == None and end_port == None : 
    start_port = int(input("Which port to start scanning from : "))
    end_port = int(input("Till which port to scan : "))

    if args.numscans is None : 
        args.numscans = 100


    if start_port < 0 or end_port > 65535: 
        sys.exit("Input invalid")

if args.ports is None : 
    num_ports = 0 
    total_ports = end_port-start_port
    start_time = datetime.now()
    print(f"Scan started at time {start_time}")

    with ThreadPoolExecutor(max_workers= args.numscans) as executor : 
        futures = {executor.submit(Scan_tcp,port) : port for port in range(start_port,end_port)}
        
        for future in concurrent.futures.as_completed(futures) :
            num_ports += 1 
            port = futures[future] 
            result = future.result()
            if num_ports%1000 == 0 : 
                print(f"{num_ports} out of {total_ports} scanned") 

            if result != 0 : 
                for v in result.values() : 
                    print(v,end = " ")
                print()

    end_time = datetime.now()
    print(f"Scan completed in : {end_time - start_time}")

    

