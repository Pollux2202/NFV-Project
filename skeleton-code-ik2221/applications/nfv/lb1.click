// 2 variables to hold ports names
define($PORT1 lb1-eth1, $PORT2 lb1-eth2)

// Define virtual IP and MAC
define($VIP 100.0.0.45/24)
define($VMAC 00-aa-bb-cc-dd-ee)

// Script will run as soon as the router starts
Script(print "Click forwarder on $PORT1 $PORT2")

// Group common elements in a single block. $port is a parameter used just to print
 elementclass L2Forwarder {$port|
 	input
        ->cnt::Counter
            ->Print
 	->Queue
 	->output
 }

// elementclass Discarder {
//   $port|
//   input
//     -> cnt::Counter
//     -> Print($port NON-IP-ARP)
//     -> Discard
// }

// From where to pick packets
from_users::FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true) //from users
from_servers::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true) //from servers

// Where to send packets
to_users:: Queue -> ToDevice($PORT1, METHOD LINUX) // to users
to_servers:: Queue -> ToDevice($PORT2, METHOD LINUX) // to servers

// Classify packets from users and servers
classify1, classify2 :: Classifier(
  12/0806 20/0001,   // ARP Request
  12/0806 20/0002,   // ARP Reply
  12/0800,           // IP Packets
  -);                // All others



classify_ip :: IPClassifier(
  dst 100.0.0.45 and icmp,        // ICMP
  dst 100.0.0.45 port 80 and tcp, // TCP
  -);

classify_ip_server :: IPClassifier(
  dst 100.0.0.45 and icmp type echo,  // ICMP to lb1
  // scr port 80 and tcp,                // TCP
  tcp,
  -
);

// ARP Responders
arp_rsp_userside :: ARPResponder($VIP $VMAC);
arp_rsp_serverside :: ARPResponder($VIP $VMAC);

// ARP Queriers
arp_que_userside :: ARPQuerier(100.0.0.45, $VMAC);
arp_que_serverside :: ARPQuerier(100.0.0.45, $VMAC);

// IPRewriter with RoundRobin backend mapping
rr :: RoundRobinIPMapper(
    100.0.0.45 - 100.0.0.40 - 0 1,
    100.0.0.45 - 100.0.0.41 - 0 1,
    100.0.0.45 - 100.0.0.42 - 0 1
  );

// rr_from_servers :: RoundRobinIPMapper(
//   - - 100.0.0.45/24 -
// );

rw :: IPRewriter(rr, rr)// - - 100.0.0.45/24 -);

// Packet counters
counter_in :: Counter;
counter_out :: Counter;

// Instantiate 2 forwarders, 1 per directions, 2 discarders
// fwd_to_servers::L2Forwarder($PORT1); // known packets from users
// fwd_to_users::L2Forwarder($PORT2); // known packets from servers
// dcd1::Discarder($PORT1); // unknown packets from users
// dcd2::Discarder($PORT2); // unknown packets from users

ipPacketToServer :: GetIPAddress(16) -> CheckIPHeader -> [0]arp_que_serverside -> to_servers;
ipPacketToClient :: GetIPAddress(16) -> CheckIPHeader -> [0]arp_que_userside -> to_users;

// Client → Server pipeline
from_users -> classify1;
classify1[0] -> Print("ARP requests from users to lb") -> arp_rsp_userside -> to_users; // ARP request to VIP
classify1[1] -> Print("ARP reply from users to lb") -> [1]arp_que_userside;             // ARP reply from client
classify1[2] -> Print("IP packets from users to lb") -> Strip(14) -> Print("(Striped)IP packets from users to lb") -> CheckIPHeader -> classify_ip;
classify1[3] -> Discard;

classify_ip[0] -> Print("ICMP packets from users to lb") -> ICMPPingResponder -> Print("(After responder)ICMP packets from users to lb") -> ipPacketToClient; //ICMP packets
classify_ip[1] -> counter_in -> [0]rw[0] -> ipPacketToServer; // IP packets to server
classify_ip[2] -> Discard;                  // all other (non-IP/ARP)

// Server → Client pipeline
from_servers -> classify2;
classify2[0] -> Print("ARP requests from servers to lb") -> arp_rsp_serverside -> to_servers;
classify2[1] -> Print("ARP reply from servers to lb") -> [1]arp_que_serverside;          // ARP from server
classify2[2] -> Print("IP packets from servers to lb") -> counter_out -> Strip(14) -> Print("(Striped)IP packets from users to lb") -> CheckIPHeader -> classify_ip_server; // IP packets to client
classify2[3] -> Discard;                  // all other (non-IP/ARP)

classify_ip_server[0] -> Print("ICMP packets from servers to lb") -> ICMPPingResponder -> Print("(After responder)ICMP packets from servers to lb") -> ipPacketToServer;
classify_ip_server[1] -> [1]rw[1] -> ipPacketToClient;
classify_ip_server[2] -> Discard;

// Print something on exit
// DriverManager will listen on router's events
// The pause instruction will wait until the process terminates
// Then the prints will run an Click will exit
DriverManager(
        print "Router starting",
        pause,
	//print "Packets from ${PORT1}: $(dcd1/cnt.count)",
	//print "Packets from ${PORT2}: $(dcd2/cnt.count)",
	//print "IP packets from clients: $(counter_in.count)",
	//print "IP packets from servers: $(counter_out.count)",
	//print "Non-IP/ARP packets from $PORT1: $(dcd1/cnt.count)",
	//print "Non-IP/ARP packets from $PORT2: $(dcd2/cnt.count)"
)
