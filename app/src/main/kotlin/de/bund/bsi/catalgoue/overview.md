# Catalogue

## Introduction
Based on the Common Criteria, a sample of common vulnerabilities and project-specific use cases, a catalogue containing concepts and queries is provided. One can use and extend these concepts and queries in a specific evaluation.

The evaluator must decide how exactly the modelling of the security function should be done. Basically, the data or control flow between two or more concepts is always examined; how exactly concepts are assigned to code components depends on how much of the system functionality is to be examined by queries and how much time and effort is to be spent on the evaluation.
While the very rough assignment of concepts (e.g. at subsystem level) is unlikely to provide any added value, the assignment at code line level is also unlikely to be very useful. As a heuristic, it can be assumed that the concepts should be assigned at the points where human experts perform the evaluation. For example, the entire implementation of AES encryption should be regarded as a single concept whose correct implementation is analysed by a human. However, a query should ensure that exactly this analysed implementation is always used in the system. In this way, the advantages of the respective approaches are reinforced.
It is recommended to start assigning concepts on the systems boundary (API-Endpoints, stored keys, stored user data, generated secrets or user data within the system) and use the tagging-api to manually extend (some of the) assigned concepts to other nodes as well. By attempting to fulfil the queries by (correctly) assigning concepts to code components, the evaluator reaches precisely those code locations that are responsible for providing the security functionality.

## Classes

### "Properties"
This section contains general properties of objects in an IT-system, regardless of its usage. Also terms used to tag high level requirements, like Asset_Confidentiality to tag an asset that shall remain confidential.

### "Cryptography"
This section contains concepts and queries concerned with the correct use and modelling of cryptographic aspects of the TOE.
In order to model the use of a protocol (i.e. the well-defined interaction between two logical identities over a communication channel), one can divide the protocol into multiple building blocks that represent the different steps one has to take to execute the protocol. For example, one can define the functions "parse(package)", "decrypt()", "generatePackage()",... and define queries that make sure that these functions are called in correct order and based on the content of package. Therefore, as long as a human checks that all submodules (substeps) are implemented correctly, this means that the components implement the protocol as specified. It follows, that the query is a different representation of the protocol's specification regarding the interaction and usage between and of different building blocks (like ciphers, paddings, look-up-tables, etc.)

Also, there are requirements on the number of usages of a key, or the timeframe in which a key might be used. Again, one should either a) point to the design decisions that make dedicated code that checks, if the rules are violated unnecessary (i.e. by sampling every key at random in every invocation) or by tagging the module that checks this property before a key is used.

### "Traversal"
This part of the catalogue contains concepts and queries concerning the correct exchange of data and information on a TOEs boundary.
It supports both local and remote ports, and both encrypted and plain import and export.
It is the evaluators responsibility to correctly tag the code, and provide the correct logic to adapt the queries to the TOE at hand.

### "Architecture"
This class is concerned with the overall design of the TOE, especially how the TOE enforces non-bypassability, domain-separation and self-protection of the TSF.


### Common Vulnerabilities
* Session Fixation
- GenAuthData_Server muss ein gutes Geheimnis erstellen
- Multi-Faktor auth ist auth mit zwei verschiedenen User-Auth-Blöcken. Falls es verschiedene Endpunkte sind, darf es keine spezifische
Fehlermeldung geben für ein falsches Passwort. die DataStore müssen verschiedenen "Domänen" angehören (Knowledge, Posession, Biometry).
- Manuelle überprüfung:
  - verify(authData): Gültigkeit, nur unter Wissen des Geheimnisses s kann Input authData generiert werden, so dass verfiy(authData) == true
    - keine typischen Sicherheitslücken in Datenbank
  - verify(uname, pw): Stelle sicher, dass (uname, h(pw)) in DataStore und der Eintrag nicht revokiert wurde
    - typische Sicherheitslücken: keine
  - GenAuthDataServer(): Nutze frischen Zufall

* UserEnumeration
- Rückgabetyp von Auth ist entweder UserID oder ein einzelner Fehler (das generierte Objekt ist stets das Gleiche)

* Schlechter PW-Rücksetzungsmechanismus
  - Link nur einmal anklickbar
  - Link braucht genügend Entropie
  - Rückmeldung muss unabhängig davon sein, ob Nutzer existiert oder nicht

* Injection
- Wenn es eine Änderung des Kontrollflusses basierend auf Nutzereingaben gibt, dann kann dies kein Datenfluss zwischen Domänen verursachen. Wenn dieser doch stattfindet, dann
- in einer DomainSeparationComponent.
- Beispiel: Die Verify(uname, pw) greift auf eine Tabelle zu, in der Daten aus verschiedenen Domänen gespeichert sind. Verify braucht manuelle überprüfung, dass keine Infos
- (über Gebühr, wie #Nutzer) geleakt werden. Eine Suche darf die Liste aller VMs anzeigen, die einem Nutzer gehören (änderung Kontrollfluss), aber nicht auf Daten zugreifen,
- die ihm nicht gehören.

Frontend Injection:
- Nutzerinput muss so bereinigt werden, dass die im Browser verwendeten Interpreter niemals Nutzerinput als Befehle verwenden. D.h. die Funktion muss angepasst werden /
- ist abhängig von der Technologie, die im Browser verwendet wird. Ist ggf. eher manuelle Prüfung. Das Frontend kann ggf. nicht zwischen validen Befehlen des Backends und
- dem Nutzerinput unterscheiden.
- Ggf. sanitisiert das Frontend ebenfalls.
- Um bei SQL eine Steuerfreiheit zu haben, braucht man sicherlich eine Input-Sanitizer(oder preparedStatements) Funktion.

* Request Forgery
