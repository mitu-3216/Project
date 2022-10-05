import streamlit as st
import nmap

import ipaddress

import re

port_range_pattern = re.compile("([0-9]+)-([0-9]+)")

port_min = 0
port_max = 65535


ip_add_entered = st.text_input("\nPlease enter the ip address that you want to scan: ")
if(st.button("Submit")):
        st.write("The IP you entered is: ", ip_add_entered)
    # If we enter an invalid ip address the try except block will go to the except block and say you entered an invalid ip address.
        try:
            ip_address_obj = ipaddress.ip_address(ip_add_entered)
            # The following line will only execute if the ip is valid.
            st.write("You entered a valid ip address.")
            
        except:
            st.write("You entered an invalid ip address")



    # You can scan 0-65535 ports. This scanner is basic and doesn't use multithreading so scanning all the ports is not advised.
st.write("Please enter the range of ports you want to scan in format: <int>-<int> (ex would be 60-120)")
port_range = st.text_input("Enter port range: ")
    # We pass the port numbers in by removing extra spaces that people sometimes enter. So if you enter 80 - 90 instead of 80-90 the program will still work.
if(st.button("Click me")):
    port_range_valid = port_range_pattern.search(port_range.replace(" ",""))

    if port_range_valid:
            # We're extracting the low end of the port scanner range the user want to scan.
            port_min = int(port_range_valid.group(1))
            # We're extracting the upper end of the port scanner range the user want to scan.
            port_max = int(port_range_valid.group(2))
            

            nm = nmap.PortScanner()
    # We're looping over all of the ports in the specified range.
            for port in range(port_min, port_max + 1):
                try:
                    # The result is quite interesting to look at. You may want to inspect the dictionary it returns. 
                    # It contains what was sent to the command line in addition to the port status we're after. 
                    # For in nmap for port 80 and ip 10.0.0.2 you'd run: nmap -oX - -p 89 -sV 10.0.0.2
                    result = nm.scan(ip_add_entered, str(port))
                    # Uncomment following line and look at dictionary
                    # print(result)
                    # We extract the port status from the returned object
                    port_status = (result['scan'][ip_add_entered]['tcp'][port]['state'])
                    st.write(f"Port {port} is {port_status}")
                except:
                    # We cannot scan some ports and this ensures the program doesn't crash when we try to scan them.
                    st.write(f"Cannot scan port {port}.")
