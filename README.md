NETWORK AUTOMATION PROJECT: MPLS Controller

Testing the application:

1) Creating the app program and the topology program and upload them on this repo for an easy access from every possible host

2) Go on the host CLI and type git clone https://github.com/AmoreAndrea/network-automation-project.git to clone everything from the repo
   --> this should be done only one time when everything is working and the App program does not need any further modification but we can easily remove the directory from the terminal by doing rm network-automation-project -r

3) Copy files in the right directory (we must be in the dir where this files actually are to perform the copy) : cp test_topo.py ~/network-automation/code-repository/project-tutorial/mininet-topologies ; cp MPLSController.py ~/network-automation/code-repository/project-tutorial/

4) Once the file are in the right directory we can start testing our app with the following commands

5) sudo mn --custom mininet-topologies/test_topo.py --topo mytopo --controller=remote -v output : to run mininet and implement the test_topo topology

6) ryu-manager flowmanager/flowmanager.py MPLSController.py --observe-links : to run the controller app

7) On the mininet terminal : h1 ping h3 or whatever other command testing the connectivity between two hosts (like iperf)
   
   
