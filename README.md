# VETO.AI

## Veto is a tool for Automated Cybersecurity Responses powered by AI (here specifically NIPRGPT)
- Currently this repo contains the code for a PROTOTYPE to demonstrate a proof of concept with the idea of monitoring systems and networks through AI-backed reasoning
- This version utilizes a self-trained anomaly detection system <- although this part of the program isn't important to the main focus of Veto, it is another area which can be improved with AI, although done by many others already

### How it Works
- by downloading the code (and either replacing the api call to NIPRGPT with your LLM of choice or including your own api key) one can navigate to the directory and install dependencies necessary for main.py and the react application
- running veto involves running main.py (to start the local flask server) then running npm run dev to start the react app (front end output)

- Veto will first utilize an Isolation Forest to create a model for anomaly detection in network packets
  - this feature can be expanded to create a model based on other activities like access, read/writes, etc. across a network utilizing system monitoring software on desired devices
- After training a simple model off the first 100 packets sniffed, Veto will begin looking for anomalies
- Once an anomaly gets detected the output of those packets gets forwarded to NIPGPT to isolate and determine what action to take based on any given information from the consumer (the ruleset) or any other needed contexts
  - this could in the future be improved with LangChain to create rulebooks or cheat sheets of commands for the AI to utilize in more complicated settings and widen the scope of options
- Depending on the decision outputted by the AI model, system commands can be executed. For demo purposes these are simple windows echo commands but this could easily be changed to manage network information by some central device or on a company server
- After a remediation is committed, the output can be logged to the front end in a simple, locally run, anomaly log. 
  
