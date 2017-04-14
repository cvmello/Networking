# !/usr/bin/python env

"""

IPv4 Subnet Calculator
Author: cmello

This code takes as input an IPv4 address and Mask. It returns:

+ Network address
+ Broadcast address
+ Network prefix
+ Wildcard mask
+ No of valid hosts per-subnet

Following IPs would be considered invalid:

+ Addresses on Multicast range
+ Addresses on Experimental reserved range
+ Loopback addresses such as 127.0.0.1 and 169.254.X.X
+ Addresses with a prefix smaller than /8.

For any improvement suggestion, feel free to reach me at cmello@cisco.com

"""

import sys


def getIP():
    while True:

        ip = raw_input("Enter IPv4 address: ")

        ip_octets = splitOctets(ip)

        if (len(ip_octets) == 4) and (1 <= int(ip_octets[0]) <= 223) and (int(ip_octets[0]) != 127) and (int(ip_octets[0]) != 169 or int(ip_octets[1]) != 254) and (0 <= int(ip_octets[1]) <= 255 and 0 <= int(ip_octets[2]) <= 255 and 0 <= int(ip_octets[3]) <= 255):
            break

        else:
            print "\nThe IP address is invalid. Please retry.\n"
            continue

    return ip


def getMask():
    while True:

        mask = raw_input("Enter subnet mask: ")

        mask_octets = splitOctets(mask)

        valid_masks = [255, 254, 252, 248, 240, 224, 192, 128, 0]

        if (len(mask_octets) == 4) and (int(mask_octets[0]) == 255) and (int(mask_octets[1]) in valid_masks) and (int(mask_octets[2]) in valid_masks) and (int(mask_octets[3]) in valid_masks) and (int(mask_octets[0]) >= int(mask_octets[1]) >= int(mask_octets[2]) >= int(mask_octets[3])):
            break

        else:
            print "\nThe mask address is invalid. Please retry.\n"
            continue

    return mask


def splitOctets(address):
    end_result = address.split(".")
    return end_result


def DecimalToBinary(address):
    octets = splitOctets(address)

    binary_octets_list = []

    for each_octet in range(0, len(octets)):
        binary_octet = bin(int(octets[each_octet]))
        binary_octet = binary_octet[2:]

        if len(binary_octet) == 8:
            binary_octets_list.append(binary_octet)
        else:
            binary_octets_list.append(binary_octet.zfill(8))

    binary_address = "".join(binary_octets_list)

    return binary_address


def getWildcard(mask):
    mask_octets = splitOctets(mask)

    wildcard_octets = []

    for each_octet in range(0, len(mask_octets)):
        octet = 255 - int(mask_octets[each_octet])
        wildcard_octets.append(str(octet))

    wildcard = ".".join(wildcard_octets)

    return wildcard


def getNetworkPrefix(mask):
    binary_mask = DecimalToBinary(mask)

    if binary_mask == "11111111111111111111111111111111":
        network_prefix = "32"
    else:
        network_prefix = binary_mask.count("1")

    return network_prefix


def getValidHosts(mask):
    binary_mask = DecimalToBinary(mask)

    total_zeroes = binary_mask.count("0")
    valid_hosts = abs(2 ** int(total_zeroes) - 2)

    return valid_hosts


def getNetworkAdd(ip, mask):
    ip_binary = DecimalToBinary(ip)
    mask_binary = DecimalToBinary(mask)

    total_zeroes = mask_binary.count("0")
    total_ones = mask_binary.count("1")

    network_address_binary = ip_binary[:total_ones] + "0" * total_zeroes

    network_address_bin_octets = []

    for each_octet in range(0, len(network_address_binary), 8):
        network_address_bin_octets.append("".join(network_address_binary[each_octet:each_octet + 8]))

    network_address_dec_octets = []

    for i in range(0, len(network_address_bin_octets)):
        network_address_dec_octets.append(str(int(network_address_bin_octets[i], 2)))

    network_address = ".".join(network_address_dec_octets)

    return network_address


def getBroadcastAdd(ip, mask):
    ip_binary = DecimalToBinary(ip)
    mask_binary = DecimalToBinary(mask)

    total_zeroes = mask_binary.count("0")
    total_ones = mask_binary.count("1")

    broadcast_address_binary = ip_binary[:total_ones] + "1" * total_zeroes

    broadcast_address_bin_octets = []

    for each_octet in range(0, len(broadcast_address_binary), 8):
        broadcast_address_bin_octets.append("".join(broadcast_address_binary[each_octet:each_octet + 8]))

    broadcast_address_dec_octets = []

    for i in range(0, len(broadcast_address_bin_octets)):
        broadcast_address_dec_octets.append(str(int(broadcast_address_bin_octets[i], 2)))

    broadcast_address = ".".join(broadcast_address_dec_octets)

    return broadcast_address


try:
    ip = getIP()
    mask = getMask()

    print "\n"
    print "Network address is: %s" % getNetworkAdd(ip, mask)
    print "Broadcast address is: %s" % getBroadcastAdd(ip, mask)
    print "Network Prefix: /%s" % getNetworkPrefix(mask)
    print "Wildcard mask: %s" % getWildcard(mask)
    print "Number of valid hosts per subnet: %s" % getValidHosts(mask)
    print "\n"

except KeyboardInterrupt:
    print "\nUser aborted.\n"
    sys.exit()
