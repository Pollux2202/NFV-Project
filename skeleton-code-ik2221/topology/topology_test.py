
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Switch
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from topology import *
import testing

topos = {'mytopo': (lambda: MyTopo())}


def run_tests(net):
    """
    Run all automated tests and print summary
    """
    h1, h2 = net.get('h1'), net.get('h2')
    llm1, llm2, llm3 = net.get('llm1'), net.get('llm2'), net.get('llm3')

    total_tests = pass_tests = 0

    def test_case(desc, func):
        nonlocal total_tests, pass_tests
        print(f"[TEST] {desc}")
        total_tests += 1
        if func():
            pass_tests += 1

    print("=========== Basic Ping ===========")
    test_case("h1 → h2 (should succeed)", lambda: testing.ping(h1, h2, True))
    #test_case("h1 → llm1 ",    lambda: testing.ping(h3, ws1, False))


    print("\n=========== Linux/SQL Injection ===========")
    injections = ["cat /etc/passwd", "cat /var/log/", "INSERT", "UPDATE", "DELETE"]
    for payload in injections:
        test_case(f"PUT with payload '{payload}' (should be blocked)",
                  lambda payload=payload: testing.curl(h1, "PUT", "/put", payload, expected=False))

    print("\n=========== Summary ===========")
    print(f"Passed {pass_tests}/{total_tests} tests.")



if __name__ == "__main__":

    # Create topology
    topo = MyTopo()

    ctrl = RemoteController("c0", ip="127.0.0.1", port=6633)

    # Create the network
    net = Mininet(topo=topo,
                  switch=OVSSwitch,
                  controller=ctrl,
                  autoSetMacs=True,
                  autoStaticArp=True,
                  build=True,
                  cleanup=True)

    # Start the network
    net.start()

    startup_services(net)
    run_tests(net)

    # Start the CLI
    CLI(net)

    # You may need some commands before stopping the network! If you don't, leave it empty
    ### COMPLETE THIS PART ###

    net.stop()
