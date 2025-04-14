# Scanneur de Malware

**_Projet développé pour offrir une solution simple mais efficace pour détecter les menaces dans les fichiers. L'objectif de ce scanner est de rendre la sécurité informatique accessible à tous. Les technologies utilisées pour développer ce projet sont :_**

+ **Python**
+ **Typescript**
+ **Next.js**
+ **Tailwind CSS**
+ **Docker**
+ **PocketBase**

## Prérequis :

+ Node.js
+ Python
+ Visual Studio Code
+ Ubuntu VM ( Pour lancer PocketBase avec docker d'installé )


## Presentation des differentes parties du projet

### 1. PocketBase

![image](https://github.com/user-attachments/assets/d6339155-d871-4028-9074-9eecc441d3d5)

_Base de données user-friendly pour permettre de comprendre plus facilement et rapidement les informations qui s'y trouvent, avec une API intégrée, une solution rapide pour développer de petits projets. Dans le cas de ce projet, Pocketbase a servi à enregistrer les utilisateurs pour pouvoir se connecter à notre compte sur le site, file_haches pour stocker les hash des fichiers malveillants (md5, sha256, etc.) pour pouvoir garder une trace et les repérer plus rapidement la prochaine fois, malware_patterns pour stocker les parties que le scanneur juge malveillantes avec leur score de menace et la réponse de l'API Virus Total pour pouvoir donner à l'utilisateur la réponse concernant son fichier._

### 2. Site Web

**Page d'accueil :**

![image](https://github.com/user-attachments/assets/53c57170-85f3-4342-a845-30481539dc5e)


**Scanner :**

![image](https://github.com/user-attachments/assets/807e436a-5bba-41c6-86aa-78f2336f9734)


_La partie avec le scanner va prendre le fichier que l'utilisateur va télécharger sur le site et va l'envoyer au backend pour qu'il fasse les analyses requises et qu'il puisse donner une réponse à l'utilisateur sur la dangerosité du fichier et le nombre de patterns malveillants trouvés également._


**Historique :**

![image](https://github.com/user-attachments/assets/807a2c40-20b7-4343-873b-bcaf44e87464)

_Cette partie va permettre à l'utilisateur d'avoir une trace des scans qu'il a effectués pour qu'il puisse éviter de les retélécharger dans le futur s'il les recroise sur internet (les utilisateurs connectés auront l'historique de leurs propres scans, tandis que les autres auront l'historique de tous les scans qui ont été récemment effectués sur le site)._

**Admin Pannel :**

![image](https://github.com/user-attachments/assets/38dbec0d-8970-4fbf-bf63-29c638f008ff)

_Le panneau d'administration va permettre aux administrateurs (les membres qui ont le statut vérifié sur Pocketbase) du site de voir différentes statistiques, comme le nombre total d'analyses, le nombre de fichiers sains/corrompus, les utilisateurs actifs, le taux de détection, etc. Ils pourront également avoir une vue sur les erreurs que le scanner rencontre pour pouvoir être plus réactifs sur le réglage de ces problèmes et donc faire évoluer le scanneur._


**Tous les droits sont réservés pour ce projet. Il est possible de l'utiliser pour des projets personnels, mais il est strictement interdit de le publier ou de le diffuser en ligne par une personne autre que le titulaire du compte actuel. Toute reproduction, modification ou distribution non autorisée est interdite.**



