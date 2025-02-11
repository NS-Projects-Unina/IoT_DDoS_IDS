import pandas as pd
import numpy as np

protocolsDict = {
    "UDP" : 1,
    "IPv4" : 2, 
    "TCP" : 3,
    "ARP" : 4,
    "ICMPv6" : 5,
    "MDNS" : 6
}

macDictBen = {
    "7e:71:27:99:4e:20" : 1,
    "fa:ef:0b:34:d0:16" : 2, 
    "56:d5:ce:38:08:cd" : 3,
}

macDictMal = {
    "26:c7:d4:c2:24:e3" : 1,
    "f6:1f:3d:7d:bc:e8" : 2, 
    "c6:a8:88:c4:ec:b5" : 3,
}

ipDict = {
    "10.0.0.1" : 1,
    "10.0.0.2" : 2, 
    "10.0.0.3" : 3,
}

# Funzione per mappare IP e MAC
def map_ip_mac(value):
    if isinstance(value, str):
        if value in macDictBen:
            return macDictBen[value]
        elif value in ipDict:
            return ipDict[value]
        else:
            return 0
    return value

# Funzione per mappare IP e MAC
def map_ip_mac_mal(value):
    if isinstance(value, str):
        if value in macDictMal:
            return macDictMal[value]
        elif value in ipDict:
            return ipDict[value]
        else:
            return 0
    return value

# Aggiungo la colonna "Label" ai file csv
csvBenigno = pd.read_csv('benigno.csv')
csvBenigno["ACK"] = csvBenigno["Info"].apply(lambda x: 1 if 'ACK' in str(x) else 0)
csvBenigno["SYN"] = csvBenigno["Info"].apply(lambda x: 1 if 'SYN' in str(x) else 0)
csvBenigno["Label"] = 0

# Modifico le colonne 'Source', 'Destination' e 'Protocol'
csvBenigno['Source'] = csvBenigno['Source'].apply(map_ip_mac)
csvBenigno['Destination'] = csvBenigno['Destination'].apply(map_ip_mac)
csvBenigno['Protocol'] = csvBenigno['Protocol'].map(protocolsDict).fillna(csvBenigno['Protocol'])

# Droppo la colonna 'Info'
csvBenigno = csvBenigno.drop(columns=['Info'])

csvBenigno.to_csv('benignoEtichettato.csv', index=False)

csvUDP = pd.read_csv('udp.csv')
csvUDP["ACK"] = csvUDP["Info"].apply(lambda x: 1 if 'ACK' in str(x) else 0)
csvUDP["SYN"] = csvUDP["Info"].apply(lambda x: 1 if 'SYN' in str(x) else 0)
csvUDP["Label"] = 1
csvUDP['Source'] = csvUDP['Source'].apply(map_ip_mac_mal)
csvUDP['Destination'] = csvUDP['Destination'].apply(map_ip_mac_mal)
csvUDP['Protocol'] = csvUDP['Protocol'].map(protocolsDict).fillna(csvUDP['Protocol'])
csvUDP = csvUDP.drop(columns=['Info'])
csvUDP.to_csv('udpEtichettato.csv', index=False)

csvSYN = pd.read_csv('syn.csv')
csvSYN["ACK"] = csvSYN["Info"].apply(lambda x: 1 if 'ACK' in str(x) else 0)
csvSYN["SYN"] = csvSYN["Info"].apply(lambda x: 1 if 'SYN' in str(x) else 0)
csvSYN["Label"] = 1
csvSYN['Source'] = csvSYN['Source'].apply(map_ip_mac_mal)
csvSYN['Destination'] = csvSYN['Destination'].apply(map_ip_mac_mal)
csvSYN['Protocol'] = csvSYN['Protocol'].map(protocolsDict).fillna(csvSYN['Protocol'])
csvSYN = csvSYN.drop(columns=['Info'])
csvSYN.to_csv('synEtichettato.csv', index=False)

# Dividi il dataset in tre parti
csvBenignoSplit = np.array_split(csvBenigno, 3)

# Salva la prima parte separatamente
csvBenignoPath = 'benignoEtichettatoSplit.csv'
csvBenignoSplit[0].to_csv(csvBenignoPath, index=False)

udpPath = 'udpEtichettato.csv'
synPath = 'synEtichettato.csv'
malignoPath = 'malignoEtichettato.csv'

# Carica i file esistenti
udpDf = pd.read_csv(udpPath)
synDf = pd.read_csv(synPath)

# Aggiungi i nuovi dati
udpDf = pd.concat([udpDf, csvBenignoSplit[1]], ignore_index=True)
synDf = pd.concat([synDf, csvBenignoSplit[2]], ignore_index=True)

# Salva i file aggiornati
udpDf.to_csv(udpPath, index=False)
synDf.to_csv(synPath, index=False)

malignoDf = pd.concat([synDf, udpDf], ignore_index=True)
malignoDf.to_csv(malignoPath, index=False)