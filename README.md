# 🔐 Lab 6 — Analyse Statique d'un APK avec MobSF
> **Cours : Sécurité des Applications Mobiles**  
> **VM : Mobexler (Kali Linux)**  
> **APK cible : DamnVulnerableBank v1.0 (`dvba.apk`)**  
> **Date d'analyse : 18/05/2026**  
> **Outil : MobSF v4.5.0**

---

## 📋 Table des matières

1. [Informations générales](#-informations-générales)
2. [Environnement d'analyse](#-environnement-danalyse)
3. [Résumé exécutif](#-résumé-exécutif)
4. [Informations sur l'APK](#-informations-sur-lapk)
5. [Task 4 — Manifeste & Permissions](#-task-4--manifeste--permissions)
6. [Task 5 — Configuration Réseau](#-task-5--configuration-réseau)
7. [Task 6 — Analyse du Code & Ressources](#-task-6--analyse-du-code--ressources)
8. [Task 7 — Corrélation OWASP MASVS](#-task-7--corrélation-owasp-masvs)
9. [Analyse Binaire (Shared Libraries)](#-analyse-binaire-shared-libraries)
10. [APKiD & Anti-Analyse](#-apkid--anti-analyse)
11. [Top Vulnérabilités & Recommandations](#-top-vulnérabilités--recommandations)
12. [Annexes](#-annexes)

---

## 📁 Informations générales

| Champ | Valeur |
|---|---|
| **APK analysé** | `dvba.apk` — DamnVulnerableBank |
| **Version** | 1.0 (code 1) |
| **Package** | `com.app.damnvulnerablebank` |
| **Taille** | 3.61 MB |
| **Outil** | MobSF v4.5.0 |
| **URL analyse** | `http://127.0.0.1:8000` |
| **Score de sécurité** | **40 / 100** 🔴 |
| **Trackers détectés** | 0 / 432 ✅ |

### Hachages de l'APK

```
MD5    : 5b40b49cd80dbe20ba611d32045b57c6
SHA1   : 23dcd688fe4dd830cf92309755a5bbd603df8789
SHA256 : 76c308fac6a655a3534771777780e004feb1d91be032857768c891b2baf40ba6
```

---

## 🛠 Environnement d'analyse

### Installation de MobSF sur Kali/Mobexler

```bash
# 1. Mise à jour système
sudo apt update && sudo apt upgrade -y

# 2. Installation Docker
sudo apt install docker.io -y
sudo systemctl start docker
sudo systemctl enable docker

# 3. Pull & lancement MobSF
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

**Accès interface :** `http://localhost:8000` — Login : `mobsf` / `mobsf`

### Récupération de l'APK

```bash
# DamnVulnerableBank
wget https://github.com/rewanthtammana/Damn-Vulnerable-Bank/releases/download/v1.0/dvba.apk
```

---

## 🚨 Résumé exécutif

L'analyse statique de **DamnVulnerableBank v1.0** révèle un **niveau de risque élevé** (score 40/100). Les principales vulnérabilités concernent :

- Le **trafic réseau non chiffré** autorisé explicitement (`usesCleartextTraffic=true`)
- Plusieurs **activités sensibles exportées sans protection** (`SendMoney`, `ViewBalance`)
- L'**absence de vérification App Link** (risque de détournement d'URL et phishing)
- La possibilité d'**installation sur Android 5.0** non patché (minSdk=21)
- Un **secret potentiellement hardcodé** (chaîne Base64 suspecte)
- Des **bibliothèques natives sans stack canary** sur certaines architectures

> ⚠️ Cette application est intentionnellement vulnérable — usage pédagogique uniquement.

---

## 📱 Informations sur l'APK

| Propriété | Valeur |
|---|---|
| **App Name** | DamnVulnerableBank |
| **Package Name** | `com.app.damnvulnerablebank` |
| **Main Activity** | `com.app.damnvulnerablebank.SplashScreen` |
| **Target SDK** | 29 (Android 10) |
| **Min SDK** | 21 (Android 5.0) |
| **Max SDK** | — |
| **Version** | 1.0 |

### Certificat de signature

```
Algorithme     : RSA / PKCS1v15 / SHA-256
Taille clé     : 2048 bits
Sujet X.509    : O=dvba, OU=dvba, CN=damncorp
Valide du      : 2020-10-29 → 2045-10-23
Signature v2   : ✅ True
Signature v1   : ❌ False (vulnérabilité Janus possible sur Android < 5.0)
```

### Composants exportés

| Type | Exportés | Total |
|---|---|---|
| Activities | 5 | 19 |
| Services | 0 | 1 |
| Receivers | 0 | 0 |
| Providers | 0 | 1 |

---

## 📄 Task 4 — Manifeste & Permissions

### Permissions demandées

| Permission | Statut | Description |
|---|---|---|
| `INTERNET` | normal | Accès réseau complet |
| `USE_BIOMETRIC` | normal | Authentification biométrique |
| `USE_FINGERPRINT` | normal ⚠️ | **Dépréciée** depuis API 28 |

> ✅ Aucune permission **dangereuse** (LOCATION, CONTACTS, SMS...) déclarée.  
> ⚠️ `INTERNET` est classifiée comme **Top Malware Permission** (1/25).

### Problèmes identifiés dans le manifeste

| N° | Sévérité | Problème |
|---|---|---|
| 1 | 🔴 HIGH | minSdk=21 → installation sur Android 5.0 non patché |
| 2 | 🔴 HIGH | `android:usesCleartextTraffic=true` — HTTP non chiffré autorisé |
| 3 | 🔵 INFO | Network Security Config présent (`network_security_config.xml`) |
| 4 | 🟡 WARNING | `android:allowBackup=true` — backup ADB possible |
| 5 | 🔴 HIGH | App Link `assetlinks.json` absent pour `http://xe.com` |
| 6 | 🔴 HIGH | App Link `assetlinks.json` absent pour `https://xe.com` |
| 7 | 🟡 WARNING | `CurrencyRates` non protégée avec intent-filter |
| 8 | 🟡 WARNING | `SendMoney` exportée sans protection (`android:exported=true`) |
| 9 | 🟡 WARNING | `ViewBalance` exportée sans protection (`android:exported=true`) |
| 10 | 🟡 WARNING | `DeviceCredentialHandlerActivity` exportée |

### Composants exportés sensibles

```
⚠️  com.app.damnvulnerablebank.SendMoney        [exported=true, sans permission]
⚠️  com.app.damnvulnerablebank.ViewBalance      [exported=true, sans permission]
⚠️  com.app.damnvulnerablebank.CurrencyRates    [intent-filter → export implicite]
⚠️  androidx.biometric.DeviceCredentialHandlerActivity [exported=true]
```

---

## 🌐 Task 5 — Configuration Réseau

### Network Security Config

| Paramètre | Valeur | Risque |
|---|---|---|
| `usesCleartextTraffic` | `true` | 🔴 **HIGH** — HTTP non chiffré autorisé |
| `networkSecurityConfig` | `@xml/network_security_config` | présent |
| Trust user certificates | `true` | 🔴 **HIGH** — Certificats utilisateur acceptés (MitM facile) |
| Trust system certificates | `true` | 🟡 WARNING |

### Résumé des alertes réseau

```
[HIGH]    Base config autorise le trafic en clair vers TOUS les domaines
[HIGH]    Base config fait confiance aux certificats installés par l'utilisateur
[WARNING] Base config fait confiance aux certificats système
```

> 🎯 **Impact :** Un attaquant sur le même réseau peut intercepter et modifier le trafic sans être détecté (attaque Man-in-the-Middle triviale).

### Endpoints & Domaines identifiés

| URL | Fichier source |
|---|---|
| `http://localhost` | `c/c/a/a/f/c/n1.java` |
| `http://schemas.android.com/apk/res/android` | `a/a/a/a/a.java` |
| `https://plus.google.com/` | `c/c/a/a/c/l/f0.java` |
| `https://www.xe.com/` | `CurrencyRates.java` |

### Domaines — Vérification malware

| Domaine | Statut | Localisation |
|---|---|---|
| `plus.google.com` | ✅ OK | Mountain View, CA, USA |
| `schemas.android.com` | ✅ OK | N/A |
| `www.xe.com` | ✅ OK | London, UK |

---

## 💻 Task 6 — Analyse du Code & Ressources

### Code Analysis

| N° | Sévérité | Problème | Standard | Fichier |
|---|---|---|---|---|
| 1 | 🔵 INFO | L'app journalise des informations sensibles dans les logs | CWE-532 / MSTG-STORAGE-3 | — |
| 2 | ✅ SECURE | Détection root possible (RootBeer) | MSTG-RESILIENCE-1 | `a/a/a/a/a.java` |
| 3 | 🟡 WARNING | Lecture/écriture sur stockage externe | CWE-276 / MSTG-STORAGE-2 | `MainActivity.java` |

### Secret hardcodé potentiel

```
Section : POSSIBLE HARDCODED SECRETS (1 trouvé)

GmdBWksdEwAZFAlLVEdDX1FKS0JtQU1DHggaBkNXQQFjTkdBTUMJBgMCFQUIFA5MXU...
[chaîne Base64 — à analyser/décoder pour confirmer]
```

> ⚠️ Ce secret doit être vérifié manuellement. Il pourrait s'agir d'une clé API, token, ou credential encodé.

### Behaviour Analysis (extrait)

| Rule ID | Comportement | Label |
|---|---|---|
| 00012 | Lecture de données dans un buffer | file |
| 00022 | Ouverture de fichier par chemin absolu | file |
| 00024 | Écriture après décodage Base64 | reflection + file |
| 00036 | Accès aux ressources `res/raw` | reflection |
| 00075 | Récupération de la localisation GPS | collection + location |
| 00089 | Connexion URL + réception stream | command + network |
| 00096 | Connexion URL + définition méthode HTTP | command + network |

### APIs Android détectées

```
Android Notifications       Base64 Decode / Encode
Certificate Handling        Crypto
Dynamic Class Loading       Execute OS Command
Get Installed Applications  Get System Service
GPS Location                (+ 10 autres)
```

---

## 🛡 Task 7 — Corrélation OWASP MASVS

### Vulnérabilités → Références MASVS

| Vulnérabilité | Référence MASVS | Description | Preuve | Impact |
|---|---|---|---|---|
| **Trafic HTTP non chiffré** | `MASVS-NETWORK-1` | Les données doivent transiter via TLS | `usesCleartextTraffic=true` dans AndroidManifest | Interception réseau (MitM), vol de credentials |
| **Certificats utilisateur acceptés** | `MASVS-NETWORK-2` | L'app ne doit pas faire confiance aux certificats non système en production | `network_security_config.xml` — trust user certs | Facilite les proxies d'intercepion (Burp, mitmproxy) |
| **Stockage externe non sécurisé** | `MASVS-STORAGE-2` | Les données sensibles ne doivent pas être stockées sur stockage externe | `MainActivity.java` — écriture externe | Toute app peut lire ces données |
| **Logs d'informations sensibles** | `MASVS-STORAGE-3` | Les données sensibles ne doivent pas apparaître dans les logs | Code Analysis — CWE-532 | Fuite via `adb logcat` |
| **Activités exportées sans protection** | `MASVS-PLATFORM-1` | Les composants IPC doivent être protégés | `SendMoney`, `ViewBalance` — `exported=true` sans permission | Toute app peut lancer un virement ou consulter le solde |
| **Backup ADB activé** | `MASVS-STORAGE-8` | Les données de l'app ne doivent pas être sauvegardables | `allowBackup=true` | Extraction des données via `adb backup` |
| **Secret potentiellement hardcodé** | `MASVS-STORAGE-14` | Les clés/secrets ne doivent pas être codés en dur | Chaîne Base64 suspecte dans les ressources | Compromission de l'API/backend |

### Tests MASTG complémentaires recommandés

| Référence MASTG | Description | Objectif |
|---|---|---|
| `MASTG-TEST-0010` | Testing for Sensitive Data in Network Traffic | Intercepter le trafic HTTP avec Burp Suite pour confirmer les données en clair |
| `MASTG-TEST-0011` | Testing for Unencrypted Sensitive Data in Local Storage | Vérifier les fichiers créés sur le stockage externe après utilisation de l'app |

---

## 🔬 Analyse Binaire (Shared Libraries)

### Bibliothèques natives présentes

```
libfrida-check.so    (x86_64, x86, armeabi-v7a, arm64-v8a)
libtool-checker.so   (x86_64, x86, armeabi-v7a, arm64-v8a)
```

### Résumé des protections binaires

| Lib | Architecture | NX | PIE | Stack Canary | RELRO | FORTIFY |
|---|---|---|---|---|---|---|
| `libfrida-check.so` | x86_64 | ✅ | ✅ DSO | ✅ | Full | ❌ warning |
| `libtool-checker.so` | x86_64 | ✅ | ✅ DSO | ❌ **HIGH** | Full | ❌ warning |
| `libfrida-check.so` | arm64-v8a | ✅ | ✅ DSO | ✅ | Full | ❌ warning |
| `libtool-checker.so` | arm64-v8a | ✅ | ✅ DSO | ❌ **HIGH** | Full | ❌ warning |
| `libtool-checker.so` | armeabi-v7a | ✅ | ✅ DSO | ✅ | Full | ❌ warning |

> 🔴 `libtool-checker.so` sur **x86_64 et arm64-v8a** est **sans stack canary** → vulnérable aux attaques de type stack buffer overflow.  
> ⚠️ Aucune bibliothèque n'a de fonctions **FORTIFY** activées.

---

## 🕵️ APKiD & Anti-Analyse

### Détections dans `classes.dex`

| Type | Détail |
|---|---|
| **Anti Debug** | `Debug.isDebuggerConnected()` check |
| **Anti-VM** | `Build.FINGERPRINT`, `Build.MODEL`, `Build.MANUFACTURER`, `Build.PRODUCT`, `Build.HARDWARE`, `Build.TAGS` checks |
| **Compilateur** | r8 |

### Détections dans les librairies natives

```
libtool-checker.so → anti_root : RootBeer
  (présent sur toutes les architectures : armeabi-v7a, x86, x86_64, arm64-v8a)
```

> L'application implémente des mécanismes anti-analyse (anti-debug, anti-VM, anti-root via RootBeer) — classifié **SECURE** par MobSF (MSTG-RESILIENCE-1). Ces protections peuvent cependant être contournées en dynamique.

---

## 🎯 Top Vulnérabilités & Recommandations

### Top 5 Vulnérabilités

| # | Titre | Sévérité | MASVS | Localisation |
|---|---|---|---|---|
| 1 | Trafic réseau non chiffré (HTTP autorisé) | 🔴 CRITICAL | MASVS-NETWORK-1 | `AndroidManifest.xml` |
| 2 | Activités sensibles exportées sans protection | 🔴 HIGH | MASVS-PLATFORM-1 | `SendMoney`, `ViewBalance` |
| 3 | Certificats utilisateur acceptés (MitM trivial) | 🔴 HIGH | MASVS-NETWORK-2 | `network_security_config.xml` |
| 4 | App Link non vérifiés (risque phishing) | 🔴 HIGH | MASVS-PLATFORM-3 | `CurrencyRates` — `xe.com` |
| 5 | Secret potentiellement hardcodé (Base64) | 🟡 MEDIUM | MASVS-STORAGE-14 | APK Resources |

### Recommandations priorisées

```
[P1] Désactiver android:usesCleartextTraffic → forcer HTTPS uniquement
     → network_security_config.xml : <base-config cleartextTrafficPermitted="false"/>

[P2] Protéger SendMoney et ViewBalance avec une permission custom ou android:exported="false"
     → Seule l'app elle-même doit pouvoir déclencher ces activités

[P3] Retirer la confiance aux certificats utilisateur en production
     → network_security_config.xml : supprimer <certificates src="user"/>

[P4] Implémenter la vérification App Link (assetlinks.json) pour xe.com
     → Ajouter android:autoVerify="true" dans le intent-filter de CurrencyRates

[P5] Auditer et supprimer le secret Base64 hardcodé
     → Le déplacer vers Android Keystore ou une solution de secrets management

[P6] Relever minSdk à 28 minimum (Android 9+) pour bénéficier des patches sécurité récents

[P7] Activer android:allowBackup="false" pour empêcher l'extraction de données via ADB
```

---

## 📎 Annexes

### A. Liste complète des activités

```
com.app.damnvulnerablebank.Myprofile
com.app.damnvulnerablebank.CurrencyRates          ⚠️ exportée (intent-filter)
com.app.damnvulnerablebank.ResetPassword
com.app.damnvulnerablebank.ViewBeneficiary
com.app.damnvulnerablebank.ApproveBeneficiary
com.app.damnvulnerablebank.PendingBeneficiary
com.app.damnvulnerablebank.AddBeneficiary
com.app.damnvulnerablebank.SendMoney              ⚠️ exportée (exported=true)
com.app.damnvulnerablebank.ViewBeneficiaryAdmin
com.app.damnvulnerablebank.GetTransactions
com.app.damnvulnerablebank.ViewBalance            ⚠️ exportée (exported=true)
com.app.damnvulnerablebank.Dashboard
com.app.damnvulnerablebank.RegisterBank
com.app.damnvulnerablebank.BankLogin
com.app.damnvulnerablebank.MainActivity
com.app.damnvulnerablebank.SplashScreen
androidx.biometric.DeviceCredentialHandlerActivity ⚠️ exportée
com.google.firebase.auth.internal.FederatedSignInActivity
com.google.android.gms.common.api.GoogleApiActivity
```

### B. SBOM — Dépendances principales

```
androidx.biometric:biometric@1.0.1
androidx.appcompat:appcompat@1.2.0
androidx.core:core@1.3.1
com.google.android.material:material@1.1.0
androidx.recyclerview:recyclerview@1.1.0
androidx.fragment:fragment@1.1.0
(+ 31 autres packages androidx)
```

### C. Commandes utiles pour analyse complémentaire

```bash
# Vérifier le hash de l'APK
sha256sum dvba.apk

# Décompiler l'APK
apktool d dvba.apk -o dvba_out/

# Extraire le code Java lisible
jadx -d dvba_jadx/ dvba.apk

# Intercepter le trafic (après install certificat Burp)
adb shell settings put global http_proxy 192.168.x.x:8080

# Lancer une activité exportée directement (PoC)
adb shell am start -n com.app.damnvulnerablebank/.SendMoney
adb shell am start -n com.app.damnvulnerablebank/.ViewBalance
```

---

## 📚 Références

- [OWASP MASVS](https://mas.owasp.org/MASVS/)
- [OWASP MASTG](https://mas.owasp.org/MASTG/)
- [MobSF Documentation](https://mobsf.github.io/docs/)
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [CWE-276 — Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)
- [CWE-532 — Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

---

> 🎓 **Lab réalisé dans un cadre pédagogique** — Cours Sécurité des Applications Mobiles  
> ⚙️ Analysé avec **MobSF v4.5.0** sur **Kali Linux / Mobexler**  
> 📅 Date : 18 mai 2026
