# Audit de Sécurité – Application Mobile "BankDroid"

## Objectif de l’étude

Cette analyse vise à évaluer la robustesse d’une application bancaire de démonstration (BankDroid) en combinant des outils d’inspection statique et dynamique, aussi bien externes qu’internes. Les résultats doivent permettre d’identifier les failles exploitables et de proposer des correctifs.

---

## Mise en place du répertoire de travail

Avant toute manipulation, l’environnement local est organisé pour séparer les résultats des différentes phases d’investigation.

    PS C:\Users\analyste\mobile-audit> dir

    Répertoire : C:\Users\analyste\mobile-audit

    | Mode    | LastWriteTime    | Length | Nom du dossier   |
    |---------|------------------|--------|------------------|
    | d-----  | 20/04/2026 19:12  |        | 00-contexte      |
    | d-----  | 20/04/2026 19:14  |        | 01-scanner-web   |
    | d-----  | 20/04/2026 19:14  |        | 02-analyse-local |
    | d-----  | 20/04/2026 19:15  |        | 03-synthese      |

    PS C:\Users\analyste\mobile-audit>

*Image : arborescence des dossiers de travail* → <img width="1470" height="704" alt="Gemini_Generated_Image_3n51z13n51z13n51" src="https://github.com/user-attachments/assets/24ba486c-43cb-4d02-8646-33877294cf1e" />


---

## Application cible

**Nom du paquet :** `com.android.insecurebankv2`  
**Version :** 1.0  
**Nature :** Application de démonstration volontairement vulnérable.

*Image : écran d’accueil de l’application* →<img width="375" height="682" alt="image" src="https://github.com/user-attachments/assets/28d6c2db-cb0f-4193-88e0-7f189b512bd1" />



---

## Empreinte cryptographique de l’APK

Une empreinte SHA‑256 est calculée afin de garantir l’intégrité du binaire analysé et de pouvoir le référencer de manière unique.

    PS C:\Users\analyste\mobile-audit> Get-FileHash "C:\Users\analyste\Downloads\BankDroid.apk" -Algorithm SHA256

    Algorithm : SHA256
    Hash      : B18AF2A9E44D7634BBDCF93664D9C78A2695E058393FCF85BE891F9020194A4
    Path      : C:\Users\analyste\Downloads\BankDroid.apk

*Image : résultat de la commande de hachage* → <img width="2866" height="352" alt="Gemini_Generated_Image_pine7upine7upine" src="https://github.com/user-attachments/assets/3f656447-6e42-4f58-a5b9-0a00ab2559c8" />

---

## Analyse de la surface d’attaque externe – Outil BeVigil

Un premier passage via un service d’analyse cloud (BeVigil) permet de détecter des problèmes de configuration exposés publiquement.

**Résultats agrégés :**  
- **Nombre de failles détectées :** 5  
- **Niveau de risque :**  
  - Élevé : 2  
  - Moyen : 2  
  - Faible : 1  

**Score de sécurité attribué :** 7,4 / 10 (moyen)

**Anomalies remontées :**  
1. Stockage d’informations sensibles dans un emplacement non protégé (simulant un bucket S3)  
2. Présence de traces (logs) contenant des mots de passe ou jetons  
3. Une activité Android est exportée sans permission  
4. Un secret potentiel (clé API, mot de passe en dur) est détecté dans le code  
5. Utilisation de requêtes HTTP en clair (pas de TLS)

*Image : tableau de bord BeVigil avec les indicateurs de risque* → <img width="1021" height="403" alt="image" src="https://github.com/user-attachments/assets/dc33b9b5-3b90-4f18-993b-102a34160254" />


---

## Analyse statique locale – Outil Yaazhini

L’APK est ensuite soumis à un scanner local pour examiner sa structure interne et ses métadonnées.

| Propriété                  | Valeur                          |
|----------------------------|----------------------------------|
| Nom de l’application       | InsecureBankv2                   |
| Paquet                     | com.android.insecurebankv2       |
| Version                    | 1.0                              |
| SDK minimal (minSdk)       | 15 (Android 4.0.3)               |
| SDK cible (targetSdk)      | 22 (Android 5.1)                 |
| Taille du fichier          | 3,3 Mo                           |

**Observations notables :**  
- La version du SDK cible est très ancienne (API 22) – elle n’impose pas le système de permissions runtime.  
- Plusieurs composants (`activity`, `service`, `receiver`) sont déclarés `exported="true"` sans contrôle d’accès.

*Image : interface du scanner Yaazhini affichant les métadonnées* → <img width="1025" height="521" alt="image" src="https://github.com/user-attachments/assets/dea3e7d9-5383-46a3-b890-078111f0bfdd" />


---

## Consolidation et triage des vulnérabilités

Les résultats des deux outils sont fusionnés et organisés selon une matrice de criticité. Les doublons sont éliminés, et chaque vulnérabilité est rattachée à une famille OWASP Mobile ASVS (MASVS).

| ID | Catégorie                | Description courte                          | Niveau de risque | Référence MASVS       |
|----|--------------------------|---------------------------------------------|------------------|------------------------|
| V1 | Stockage de données      | Mots de passe en clair dans la base locale  | 🔴 Critique      | MSTG-STORAGE-1         |
| V2 | Logs sensibles           | Informations de connexion écrites dans logcat | 🔴 Élevé       | MSTG-STORAGE-3         |
| V3 | Communication réseau     | Échanges en HTTP (non chiffré)              | 🔴 Critique      | MSTG-NETWORK-1         |
| V4 | Composants exportés      | Activité `PostLogin` accessible sans permission | 🟠 Moyen       | MSTG-PLATFORM-1        |
| V5 | SDK obsolète             | targetSdk=22 ; pas de scoped storage        | 🟠 Moyen         | MSTG-PLATFORM-4        |



---

## Description détaillée des vulnérabilités principales

### V1 – Stockage non sécurisé
Les identifiants utilisateur sont conservés dans un fichier de préférences partagées (`shared_prefs`) en clair. Un attaquant ayant un accès physique ou via un débogueur peut les lire.

### V2 – Fuite via les logs
L’application écrit dans le log système des informations sensibles (nom d’utilisateur, mot de passe, token de session) lors de l’authentification. Toute autre application disposant de la permission `READ_LOGS` peut les intercepter.

### V3 – Absence de TLS
Le trafic réseau vers le backend utilise le protocole HTTP non chiffré. Un attaquant de type « homme du milieu » sur le même réseau peut capturer l’intégralité des échanges.



---

## Recommandations techniques

Pour chaque faille identifiée, une ou plusieurs actions correctives sont proposées :

1. **Chiffrement des données sensibles**  
   Utiliser `EncryptedSharedPreferences` (AndroidX Security) ou un chiffrement symétrique (AES) avec une clé dérivée du keystore Android.

2. **Désactivation des logs en production**  
   Wrapper les appels à `Log.d()`, `Log.i()` avec un flag `BuildConfig.DEBUG` ou utiliser ProGuard pour supprimer les appels dans la version release.

3. **Forçage de HTTPS**  
   Configurer le `NetworkSecurityConfig` pour interdire le trafic HTTP. Utiliser le paramètre `cleartextTrafficPermitted="false"` dans le manifeste.

4. **Restriction des composants exportés**  
   Passer `android:exported="false"` sur les activities, services et receivers qui ne nécessitent pas d’interopérabilité. Si l’exportation est indispensable, définir des permissions personnalisées avec `protectionLevel="signature"`.

5. **Mise à jour du SDK**  
   Élever `targetSdkVersion` à au moins 29 (Android 10) pour bénéficier des améliorations de sécurité (stockage partitionné, restrictions des permissions).



---

## Plan d’action priorisé

| Priorité | Action                             | Délai estimé |
|----------|------------------------------------|---------------|
| Urgent   | Passer HTTPS – interdire HTTP       | 1 jour        |
| Urgent   | Chiffrer les préférences partagées  | 2 jours       |
| Élevée   | Supprimer les logs sensibles        | 1 jour        |
| Moyenne  | Réviser l’exportation des composants | 3 jours       |
| Faible   | Monter le niveau du SDK             | 5 jours (tests) |



---

## Synthèse des résultats

L’audit de **BankDroid** (com.android.insecurebankv2) révèle des manquements graves en matière de sécurité, typiques des applications développées sans connaissance des bonnes pratiques Android. Les trois risques critiques (stockage en clair, fuite par logs, HTTP clair) exposent directement les utilisateurs à une compromission totale de leur compte. Néanmoins, toutes ces failles sont corrigeables sans refonte architecturale majeure.



---

## Conclusion finale

Cette analyse montre l’importance d’une approche multi‑outils (analyse externe + interne) pour couvrir l’ensemble des vulnérabilités potentielles. Les correctifs proposés, s’ils sont appliqués, élèveraient significativement le niveau de sécurité de l’application, tout en respectant les standards OWASP MASVS.



---

**Note pour l’intégration des captures d’écran :**  
Les fichiers image doivent être placés dans le dossier `./images/` et nommés respectivement `1.png`, `2.png`, `3.png`, `4.png`, `5.png`, `6.png`, `7.png`, `8.png`, `9.png`, `10.png`, `11.png`. L’ordre d’apparition dans le document suit exactement cet index.
