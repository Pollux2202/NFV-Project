// 2 variables to hold ports names
define($PORT1 napt-eth1, $PORT2 napt-eth2)

// Define IPs and MACs
define($INTERNAL_IP 10.0.0.1/24)
define($EXTERNAL_IP 100.0.0.1/24)
define($INTERNAL_MAC 00-aa-bb-cc-dd-01)
define($EXTERNAL_MAC 00-aa-bb-cc-dd-02)

// Script will run as soon as the router starts
Script(print "NAPT Click router running with L2Forwarders on $PORT1 <--> $PORT2")

// Custom buffered forwarder element
elementclass L2Forwarder {$port|
  input
    -> cnt::Counter
        -> Print
    -> Print($port FORWARDED)
    -> Queue
    -> output
}

// ARP handlers
arp_rsp_int :: ARPResponder($INTERNAL_IP $INTERNAL_MAC);
arp_rsp_ext :: ARPResponder($EXTERNAL_IP $EXTERNAL_MAC);
arp_que_int :: ARPQuerier(10.0.0.1, $INTERNAL_MAC);
arp_que_ext :: ARPQuerier(100.0.0.1, $EXTERNAL_MAC);

// Rewriters
iprw :: IPRewriter(pattern 100.0.0.1 1024-65535 - - 0 1);
icmprw :: ICMPPingRewriter(pattern 100.0.0.1 - - 0 1);

// Classifiers
classify1, classify2 :: Classifier(
  12/0806 20/0001,   // ARP request
  12/0806 20/0002,   // ARP reply
  12/0800,           // IP (TCP/UDP/etc.)
  -);                // All others

// IPClasifier, need to use with IP packets
ipclassifier_to_lb, ipclassifier_to_users :: IPClassifier(
  tcp,
  icmp type echo,
  icmp type echo-reply,
  -
);

// From and To devices
from_users :: FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true);
from_servers :: FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true);
to_users :: Queue -> ToDevice($PORT1, METHOD LINUX);
to_servers :: Queue -> ToDevice($PORT2, METHOD LINUX);

// Forwarders with buffering + logging
// out_icmp_fwd :: L2Forwarder($PORT1);
// out_tcp_fwd  :: L2Forwarder($PORT1);
// in_icmp_fwd  :: L2Forwarder($PORT2);
// in_tcp_fwd   :: L2Forwarder($PORT2);

// Client → Server
from_users -> classify1;
classify1[0] -> Print("arp requests from user to lb") -> arp_rsp_int -> to_users;  //arp request
classify1[1] -> Print("arp respond from user to lb") -> [1]arp_que_int;           //arp respond
classify1[2] -> Print("IP packets from users to lb") -> Strip(14) -> CheckIPHeader -> ipclassifier_to_lb;  //IP packets
classify1[3] -> Discard;

ipclassifier_to_lb[0] -> Print("TCP from users to lb") -> iprw[0] -> [0]arp_que_ext[0] -> to_servers;
ipclassifier_to_lb[1] -> Print("ICMP echo from users to lb") -> icmprw[0] -> [0]arp_que_ext[0] -> to_servers;
ipclassifier_to_lb[2] -> Print("ICMP echo reply from uesrs to lb") -> icmprw[0] -> [0]arp_que_ext[0] -> to_servers;
ipclassifier_to_lb[3] -> Discard;

// arp_que_ext[1] -> to_servers;

// Server → Client
from_servers -> classify2;
classify2[0] -> Print("arp requests from lb to users") -> arp_rsp_ext -> to_servers;  //arp request
classify2[1] -> Print("arp reply from lb to users") -> [1]arp_que_ext;           //arp respond
classify2[2] -> Strip(14) -> CheckIPHeader -> ipclassifier_to_users;  //IP packets
classify2[3] -> Discard;

ipclassifier_to_users[0] -> Print("TCP from lb to users") -> iprw[1] -> [0]arp_que_int[0] -> to_users;
ipclassifier_to_users[1] -> Print("ICMP echo from lb to users") -> icmprw[1] -> [0]arp_que_int[0] -> to_users;
ipclassifier_to_users[2] -> Print("ICMP echo reply from lb to users") -> icmprw[1] -> [0]arp_que_int[0] -> to_users;
ipclassifier_to_users[3] -> Discard;

// arp_que_ext[1] -> to_users;

// Monitoring
DriverManager(
  print "NAPT initialized with L2Forwarder queues.",
  pause,
  //print "Outbound TCP packets: $(out_tcp_fwd/cnt.count)",
  //print "Outbound ICMP packets: $(out_icmp_fwd/cnt.count)",
  //print "Inbound TCP packets: $(in_tcp_fwd/cnt.count)",
  //print "Inbound ICMP packets: $(in_icmp_fwd/cnt.count)"
)