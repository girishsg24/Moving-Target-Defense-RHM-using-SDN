# Moving-Target-Defense-RHM-using-SDN

Developed a Moving Target Defense mechanism to prevent IP scanning from inside & outside the network. 
Controlled the packet flow in a SDN based on Random host mutation technique. 
Developed the a new routing mechanism using north bound API provided by controller using multithreading, decorators, event creation & event handling techniques. 
Performed extensive testing and evaluation on OpenFlow protocol & RYU controller using python.

# Demo https://youtu.be/MUDFubJE8HM

In this project, the network assets are hidden from the external and internal attackers. The OpenFlow Controller is programmed smartly to perform the IP Mutation technique. This technique changes the Real IP Addresses of the underlying hosts by assigning them a Virtual IP address at a high mutation rate. The Virtual IPs are extracted from the pool of unassigned IP addresses generated using pseudo random number generator ensuring high unpredictability.

Developed an self learning algorithm to attain automation. 

# Detailed Algorithm
1. The main aim of the project was to prevent IP scanning, by having a dynamic address allocation.
2. In this scheme Each host in the network has 2 addresses, one being real & other being virtual.
3. Communication between real IP address is blocked & allows only communication on virtual Ip addresses.
4. So even If an attacker gets the information about the target, it gets changed after a certain time out.
5. The only assumption is that the communication between hosts in the network happens using domain names.
6. I implemented this using a technique called random host mutation published on an IEEE paper.
7. The setup involves aRyu as an SDN controller & openvswitches as the dataplane devices.
8. So When a host wants to send a ping to another host, it first tries to resolve a domain name.
9. The request is intercepted by the controller and it acts like a proxy server, It crafts a dns response with an virtual address as the answer.
10. Internally, SDN controller holds a set of real to virtual IP mappings which time out from time to time.
11. But the problem is that an end host would not respond to a packet destined to a virtual IP address.
12. In fact, the hosts are abstracted from this virtual addressing concept.
13. SDN controller intercepts all packets at the ingress and swaps the real Src IP address with its virtual address
14. At the Egress it swaps the virtual destination IP address with its real address.
15. Controller also takes care to installs flow rules using Openflow protocol to handle the similar scenario at the data plane in future.
16. After a certain duration the real IP address to virtual IP address mappings are replaced with a new set, the flow rules in the switches are removed & packets start to drop.
17. To continue communication, the hosts has to again resolve the domain name.
18. The controller program was done using a multithreaded approach to have synchronization.
19. And programming was done in Python & Ryu API.

