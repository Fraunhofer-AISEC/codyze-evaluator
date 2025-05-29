#!/usr/bin/env kotlin

//Query to avoid injection attacks

//- Wenn es eine Änderung des Kontrollflusses basierend auf Nutzereingaben gibt, dann kann dies kein Datenfluss zwischen Domänen verursachen. Wenn dieser doch stattfindet, dann
//- in einer DomainSeparationComponent.
//- Beispiel: Die Verify(uname, pw) greift auf eine Tabelle zu, in der Daten aus verschiedenen Domänen gespeichert sind. Verify braucht manuelle überprüfung, dass keine Infos
//- (über Gebühr, wie #Nutzer) geleakt werden. Eine Suche darf die Liste aller VMs anzeigen, die einem Nutzer gehören (änderung Kontrollfluss), aber nicht auf Daten zugreifen,
//- die ihm nicht gehören.

/**
 * Every TOE has at least 3 domains: The outside, the data to be protected from the outside and at least one internal domain in which data can be processed that comes from
 * various different domains an is to be verified (user authentication data), sanitized (error messages), transformed (writing layer 2 network packets into layer 3 packets)
 * and rerouted (mapping the public IP of a VPN-client to its internal address).
 * Most likely in a cloud system, there are much more domains, and some domains might even overlap or depend on who's asking and what are his permissions.
 *
 * We have to make sure, that the TOEs behaviour do not depend in a way on user input that allows the user to bypass separation mechanisms.
 * Therefore, we forbid dependency of the control flow on user input if the subprogram executed has access to a resource container that contains resources of different domains,
 * and there are some inputs that make the subprogram access resources of a different domain than 
 */
fun controlDependencyOnUserData_cannotCauseInterDomainDataFlow()