# IDS in una rete IoT SDN OpenFlow
## Obiettivi
L'obiettivo del progetto è stato quello di sviluppare un IDS integrato nel controller della rete SDN simulata con il software Mininet. In particolare l'IDS raccoglie tutti i pacchetti della rete in modo da identificare eventuali attacchi di tipo SYN e UDP Flood.

## Installazione
E' necessario utilizzare una VM Ubuntu 22.04 e installare i seguenti pacchetti da terminale:

'''bash
sudo apt install git
sudo apt install python3-pip
sudo pip3 install pandas
pip install ryu
sudo apt install d-itg
sudo apt install nload
'''

