// 2 variables to hold ports names
define($SW2PORT ids-eth1, $INSPPORT ids-eth2, $LBPORT ids-eth3)


// Script will run as soon as the router starts
Script(print "Click forwarder on $SW2PORT $INSPPORT $LBPORT")

// since it's an ids, it doesn't need to handle ARP request
classifier :: Classifier(
	12/0806 20/0001,   // ARP request
  	12/0806 20/0002,   // ARP reply
	12/0800,	// IP
	-			// others
);

// to classify between http requests from the client side and others
ipClassifier :: IPClassifier(
	src host 100.0.0.1 and dst tcp port 80, 	// HTTP
	-	//others
);

// classify the mothod in http request
httpClassifier :: Classifier(
	66/504F5354, // POST
	66/50555420, // PUT
	- // others
);

// using the Search element to direct the pointer to the first byte of HTTP payload
search :: Search("\r\n\r\n");

putClassifier :: Classifier(
	0/636174202f6574632f706173737764,		//cat/etc/passwd 
	0/636174202f7661722f6c6f67,    		    //cat/var/log 
	0/494E53455254,                  		//INSERT 
	0/555044415445,                  		//UPDATE 
	0/44454C455445, 						// DELETE
	-
);

// Instantiate counters
arpRequestcn, arpReplycn, ipcn, httpcn, postcn, putcn :: Counter;
switchIncn, swithchOutcn, serverIncn, serverOutcn, toInspcn :: AverageCounter;

// From where to pick packets
fromSwitch :: FromDevice($SW2PORT, SNIFFER false, METHOD LINUX, PROMISC true);
fromLb :: FromDevice($LBPORT, SNIFFER false, METHOD LINUX, PROMISC true);

// Where to send packets
toSwitch :: Queue -> swithchOutcn -> ToDevice($SW2PORT, METHOD LINUX);
toLb :: Queue -> serverOutcn -> ToDevice($LBPORT, METHOD LINUX);
// toInsp :: Queue -> toInspcn -> ToDevice($INSPPORT, METHOD LINUX);
toInsp :: Queue -> ToDevice($INSPPORT, METHOD LINUX);

// the ids only need to check the packets from clien side
fromSwitch -> switchIncn -> classifier;
classifier[0] -> Print("arp requests to lb") -> arpRequestcn -> toLb;
classifier[1] -> Print("arp reply to lb") -> arpReplycn -> toLb;
classifier[2] -> ipcn -> Print("some ip packets to lb") -> Strip(14) -> CheckIPHeader -> IPPrint("(Striped)some ip packets to lb") -> ipClassifier;
classifier[3] -> toLb;

ipClassifier[0] -> httpcn -> Unstrip(14) -> httpClassifier;
ipClassifier[1] -> Unstrip(14) -> toLb;

httpClassifier[0] -> postcn -> toLb;
httpClassifier[1] -> putcn -> search -> putClassifier;
httpClassifier[2] -> toInspcn -> toInsp;

putClassifier[0] -> toInsp;
putClassifier[1] -> toInsp;
putClassifier[2] -> toInsp;
putClassifier[3] -> toInsp;
putClassifier[4] -> toInsp;
putClassifier[5] -> toLb;

// from LB side, just forward the frame
fromLb -> serverIncn -> toSwitch;

// Print something on exit
// DriverManager will listen on router's events
// The pause instruction will wait until the process terminates
// Then the prints will run an Click will exit
DriverManager(
    print "===================== IDS starting ================= \n",
    pause,
	print "Input packets rate of from switch2 (pps): $(switchIncn.rate) number $(switchIncn.count)\n",
	print "Input packets rate of from LB (pps): $(serverIncn.rate) number $(serverIncn.count)\n",
	print "Output packets rate of to switch (pps): $(swithchOutcn.rate) number $(swithchOutcn.count)\n",
	print "Output packets rate of to LB (pps): $(serverOutcn.rate) number $(serverOutcn.count)\n",
	print "Output packets rate of to Inspeter (pps): $(toInspcn.rate) number $(toInspcn.count) \n",
	print "\n",
	print "IP Packets from switch2: $(ipcn.count) \n",
	print "ARP request from switch2: $(arpRequestcn.count) \n",
	print "ARP reply to switch2: $(arpReplycn.count) \n",
	print "HTTP Packets from switch2: $(httpcn.count) \n",
	print "HTTP(PUT) Packets from switch2: $(putcn.count) \n",
	print "HTTP(POST) Packets from switch2: $(postcn.count) \n",
	print "========================== END ======================= \n"
);
