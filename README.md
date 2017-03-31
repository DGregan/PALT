# PALT - Packet Analyzing Learning Tool


Learning about Network Traffic for the first time can be a challenging experience for a
Computer networking novice or student. Packet Analysing Learning Tool (PALT) will attempt to erode
the arduous task of mastering the fundamentals of Networking Traffic. 
PALT is a web application built to assist in understanding of the contents of Network Traffic. 

This will be accomplished by providing an environment where
users can learn about network traffic through the capture of live traffic and the dissecting of
packets travelling across the network. The captured network packets will then be inspected and return
the analysed contents to the users.

Built with Python using the Flask Microframework to create a web application. The front-end will be made with a combination of Jinja2 template engine, HTML5, CSS, JavaScript. The network traffic will be acquired from a Live network device on the system. Pyshark is a wrapper for a terminal-based network protocol analyser that will be utilised to capture the network packets and will be displayed through the assistance of the Pandas data analysis library. Pyshark 
is a wrapper for ‘tshark’ which is the popular terminal-based Wireshark network protocol analyser.