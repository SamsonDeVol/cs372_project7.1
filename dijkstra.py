import sys
import json
import math  # If you want to use math.inf for infinity


def ipv4_to_value(ipv4_addr):
    """
    Convert a dots-and-numbers IP address to a single numeric value.

    Example:

    There is only one return value, but it is shown here in 3 bases.

    ipv4_addr: "255.255.0.0"
    return:    0xffff0000 0b11111111111111110000000000000000 4294901760

    ipv4_addr: "1.2.3.4"
    return:    0x01020304 0b00000001000000100000001100000100 16909060
    """
    
    bytes = ["", "", "", ""]
    value = 0
    bytes[0], bytes[1], bytes[2], bytes[3] = ipv4_addr.split('.')
    for i in range(len(bytes)):
        bytes[i] = int(bytes[i]) << (24-(i*8))
        value += bytes[i]
    return value

def value_to_ipv4(addr):
    """
    Convert a single 32-bit numeric value to a dots-and-numbers IP
    address.

    Example:

    There is only one input value, but it is shown here in 3 bases.

    addr:   0xffff0000 0b11111111111111110000000000000000 4294901760
    return: "255.255.0.0"

    addr:   0x01020304 0b00000001000000100000001100000100 16909060
    return: "1.2.3.4"
    """
    values = []
    for i in range(4):
        values.append(addr & 0b11111111  )
        addr = addr >> 8
    values.reverse()
    values = '.'.join(str(x) for x in values)
    return values
    
def get_subnet_mask_value(slash):
    """
    Given a subnet mask in slash notation, return the value of the mask
    as a single number. The input can contain an IP address optionally,
    but that part should be discarded.

    Example:

    There is only one return value, but it is shown here in 3 bases.

    slash:  "/16"
    return: 0xffff0000 0b11111111111111110000000000000000 4294901760

    slash:  "10.20.30.40/23"
    return: 0xfffffe00 0b11111111111111111111111000000000 4294966784
    """
    value = 0
    for i in range(32):
        if i < int(slash.split('/')[1]): 
            value = (value << 1) + 1
        else:
            value = (value << 1)
    return value

def ips_same_subnet(ip1, ip2, slash):
    """
    Given two dots-and-numbers IP addresses and a subnet mask in slash
    notataion, return true if the two IP addresses are on the same
    subnet.

    FOR FULL CREDIT: this must use your get_subnet_mask_value() and
    ipv4_to_value() functions. Don't do it with pure string
    manipulation.

    This needs to work with any subnet from /1 to /31

    Example:

    ip1:    "10.23.121.17"
    ip2:    "10.23.121.225"
    slash:  "/23"
    return: True
    
    ip1:    "10.23.230.22"
    ip2:    "10.24.121.225"
    slash:  "/16"
    return: False
    """
    ip1_value = ipv4_to_value(ip1)
    ip2_value = ipv4_to_value(ip2)
    subnet_mask = get_subnet_mask_value(slash)
    return (ip1_value & subnet_mask) == (ip2_value & subnet_mask)

def get_network(ip_value, netmask):
    """
    Return the network portion of an address value.

    Example:

    ip_value: 0x01020304
    netmask:  0xffffff00
    return:   0x01020300
    """
    return ip_value & netmask

def find_router_for_ip(routers, ip):
    """
    Search a dictionary of routers (keyed by router IP) to find which
    router belongs to the same subnet as the given IP.

    Return None if no routers is on the same subnet as the given IP.

    FOR FULL CREDIT: you must do this by calling your ips_same_subnet()
    function.

    Example:

    [Note there will be more data in the routers dictionary than is
    shown here--it can be ignored for this function.]

    routers: {
        "1.2.3.1": {
            "netmask": "/24"
        },
        "1.2.4.1": {
            "netmask": "/24"
        }
    }
    ip: "1.2.3.5"
    return: "1.2.3.1"


    routers: {
        "1.2.3.1": {
            "netmask": "/24"
        },
        "1.2.4.1": {
            "netmask": "/24"
        }
    }
    ip: "1.2.5.6"
    return: None
    """
    for address in routers:
        slash = routers[address]["netmask"]
        if ips_same_subnet(address, ip, slash):
            return address
    return None

def usage():
    print("usage: netfuncs.py infile.json", file=sys.stderr)

def read_routers(file_name):
    with open(file_name) as fp:
        json_data = fp.read()
        
    return json.loads(json_data)

def print_routers(routers):
    print("Routers:")

    routers_list = sorted(routers.keys())

    for router_ip in routers_list:

        # Get the netmask
        slash_mask = routers[router_ip]["netmask"]
        netmask_value = get_subnet_mask_value(slash_mask)
        netmask = value_to_ipv4(netmask_value)

        # Get the network number
        router_ip_value = ipv4_to_value(router_ip)
        network_value = get_network(router_ip_value, netmask_value)
        network_ip = value_to_ipv4(network_value)

        print(f" {router_ip:>15s}: netmask {netmask}: " \
            f"network {network_ip}")

def print_same_subnets(src_dest_pairs):
    print("IP Pairs:")

    src_dest_pairs_list = sorted(src_dest_pairs)

    for src_ip, dest_ip in src_dest_pairs_list:
        print(f" {src_ip:>15s} {dest_ip:>15s}: ", end="")

        if ips_same_subnet(src_ip, dest_ip, "/24"):
            print("same subnet")
        else:
            print("different subnets")

def print_ip_routers(routers, src_dest_pairs):
    print("Routers and corresponding IPs:")

    all_ips = sorted(set([i for pair in src_dest_pairs for i in pair]))

    router_host_map = {}

    for ip in all_ips:
        router = find_router_for_ip(routers, ip)
        
        if router not in router_host_map:
            router_host_map[router] = []

        router_host_map[router].append(ip)

    for router_ip in sorted(router_host_map.keys()):
        print(f" {router_ip:>15s}: {router_host_map[router_ip]}")

def initialize_dijkstras(routers, source):
    """
    given routers directory and source router initialize 
    and return data structures and set source distance to zero
    """
    to_visit = []
    distance = {}
    parent = {}
    for router in routers:
        to_visit.append(router)
        distance[router] = math.inf
        parent[router] = None
    distance[source] = 0
    return to_visit, distance, parent

def get_next_node_distance(routers, cur_n, nxt_n):
    """
    given the routers directory, find current nodes connection to next node
    and return the distance to that node, aka the 'ad' value
    """
    current_connections = routers[cur_n]['connections']
    next_distance = current_connections[nxt_n]['ad']
    return next_distance

def get_path(parent, src, dest):
    """
    given the source and destination routers
    retrace the parents dictionary 
    and return the re-reversed path of routers
    """
    cur_n = dest
    path = []
    while cur_n != src:
        path.append(cur_n)
        cur_n = parent[cur_n]
    path.append(src)
    path.reverse()
    return path

def dijkstras_shortest_path(routers, src_ip, dest_ip):

    """
    This function takes a dictionary representing the network, a source
    IP, and a destination IP, and returns a list with all the routers
    along the shortest path.

    The source and destination IPs are **not** included in this path.

    Note that the source IP and destination IP will probably not be
    routers! They will be on the same subnet as the router. You'll have
    to search the routers to find the one on the same subnet as the
    source IP. Same for the destination IP. [Hint: make use of your
    find_router_for_ip() function from the last project!]

    The dictionary keys are router IPs, and the values are dictionaries
    with a bunch of information, including the routers that are directly
    connected to the key.

    This partial example shows that router `10.31.98.1` is connected to
    three other routers: `10.34.166.1`, `10.34.194.1`, and `10.34.46.1`:

    {
        "10.34.98.1": {
            "connections": {
                "10.34.166.1": {
                    "netmask": "/24",
                    "interface": "en0",
                    "ad": 70
                },
                "10.34.194.1": {
                    "netmask": "/24",
                    "interface": "en1",
                    "ad": 93
                },
                "10.34.46.1": {
                    "netmask": "/24",
                    "interface": "en2",
                    "ad": 64
                }
            },
            "netmask": "/24",
            "if_count": 3,
            "if_prefix": "en"
        },
        ...

    The "ad" (Administrative Distance) field is the edge weight for that
    connection.

    **Strong recommendation**: make functions to do subtasks within this
    function. Having it all built as a single wall of code is a recipe
    for madness.
    """
    source_router = find_router_for_ip(routers, src_ip)
    destination_router = find_router_for_ip(routers, dest_ip)

    # return [] if same subnet for source and destination
    subnet_mask_value = routers[source_router]['netmask']
    if ips_same_subnet(source_router, destination_router, subnet_mask_value):
        return []

    # initialize dijkstras data structures
    to_visit, distance, parent = initialize_dijkstras(routers, source_router)

    while len(to_visit) != 0:

        # set current node to router with minimum distance 
        current_node = min(to_visit, key=distance.get)
        to_visit.remove(current_node)

        # check neighbor routers in 
        for next_node in routers[current_node]['connections']:
            if next_node in to_visit:

                # get total distance from current node and 
                total_distance = distance[current_node] + get_next_node_distance(routers, current_node, next_node)
                
                # check if this is the way
                if total_distance < distance[next_node]:
                    distance[next_node] = total_distance
                    parent[next_node] = current_node

    return get_path(parent, source_router, destination_router)
        

#------------------------------
# DO NOT MODIFY BELOW THIS LINE
#------------------------------
def read_routers(file_name):
    with open(file_name) as fp:
        data = fp.read()

    return json.loads(data)

def find_routes(routers, src_dest_pairs):
    for src_ip, dest_ip in src_dest_pairs:
        path = dijkstras_shortest_path(routers, src_ip, dest_ip)
        print(f"{src_ip:>15s} -> {dest_ip:<15s}  {repr(path)}")

def usage():
    print("usage: dijkstra.py infile.json", file=sys.stderr)

def main(argv):
    try:
        router_file_name = argv[1]
    except:
        usage()
        return 1

    json_data = read_routers(router_file_name)

    routers = json_data["routers"]
    routes = json_data["src-dest"]

    find_routes(routers, routes)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
    
