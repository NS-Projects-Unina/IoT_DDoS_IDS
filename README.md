# IDS in una rete IoT SDN OpenFlow
## Obiettivi
L'obiettivo del progetto è stato quello di sviluppare un IDS integrato nel controller della rete SDN simulata con il software [Mininet](https://github.com/mininet/mininet/wiki/Introduction-to-Mininet). In particolare l'IDS raccoglie tutti i pacchetti della rete in modo da identificare eventuali attacchi di tipo SYN e UDP Flood.

## Installazione
1) E' necessario utilizzare una VM Ubuntu 22.04 e installare i seguenti pacchetti da terminale:

```bash
sudo apt install git
sudo apt install python3-pip
sudo pip3 install pandas
pip install ryu
sudo apt install d-itg
sudo apt install nload
```
2) Clonare la repository di Mininet e installare le dipendenze necessarie
```bash
git clone https://github.com/mininet/mininet
cd mininet
git tag
git checkout -b mininet-2.3.0 2.3.0
cd ..
sudo PYTHON=python3 mininet/util/install.sh -nv
```
3) Test dell'installazione
```bash
sudo mn --switch ovsbr --test pingall # Test Mininet installation
```
## Raccolta dei dataset
Gli attacchi e la relativa raccolta dei pacchetti si è svolta seguendo i seguenti comandi:
1) Avvio della rete
```bash
source ambiente_ryu/bin/activate                                     # utilizzo un ambiente virtuale python3.9 
                                                                     # per compatibilità con ryu
python3.9 -m ryu.cmd.manager controller.py          
sudo python3 topology.py                                             # avvia la topologia
xterm h1 h2 h3                                                       # accedo ai terminali dei nodi
```
