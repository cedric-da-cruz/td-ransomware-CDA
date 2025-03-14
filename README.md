# td-ransomware-CDA
Td ransomware

Q1 : c'est un chiffrement XOR, il n'est pas très robuste car on va pouvoir utilisé de l'analyse statistique pour déchiffrer (plus la clé sera courte plus le déchiffrement sera facile)

Q2 : Car sinon le on peut facilement brute force ou faire un déchiffrement par analyse statistique. Le hmac va permettre de réduire la faiblesse face à ces 2 méthodes

Q3 : si on stock dans /root/token il ne faudrait pas supprimer un précedent token.bin, je suppose que si la personne avait été une cible précedente on ne voudarit pas recommencer le processus pour rien
