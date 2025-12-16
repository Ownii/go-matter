# Go-Matter SDK

Dieses Projekt ist eine Implementierung des Matter Smart Home Protokoll-Standards in Go.
Ziel ist es, ein funktionierendes, verständliches und modulares SDK zu erstellen, welches sowohl die Device-Seite (Accessories) als auch die Controller-Seite (Commissioners/Fabric Admins) abdeckt.

Das Projekt befindet sich aktuell in der **Scaffolding / Prototyping Phase**.

## 🏗 Status des Projekts

### ✅ Implementiert

*   **TLV (Tag-Length-Value)**
    *   Vollständiger `Encoder` und `Decoder` für Matter-konformes TLV.
    *   Unterstützung für Basis-Typen, Container (Structs, Arrays, Lists) und `omitempty`.
    *   Unit Tests und Loopback-Verification.
*   **Transport Layer (Basis)**
    *   Grundlegendes UDP-Framework (`TransportManager`).
    *   Senden und Empfangen von Nachrichten per Callback-Handler.
*   **Commissioning (PASE - Passcode Authenticated Session Establishment)**
    *   Grundgerüst für die PASE State Machine.
    *   Data Structs für `PBKDFParamRequest` und `PBKDFParamResponse` mit TLV-Tags.
    *   Logic für den Austausch der ersten Handshake-Nachrichten.
*   **Samples**
    *   `samples/commissioning/device`: Ein Beispielgerät, das auf UDP lauscht und PASE-Anfragen beantwortet (Stub).
    *   `samples/commissioning/controller`: Ein Beispielcontroller, der den Handshake initiiert.

### 🚧 In Arbeit / Geplant

1.  **Kryptografie vervollständigen**
    *   Vollständige Integration von **SPAKE2+** (via `crypto` Package).
    *   Berechnung des Shared Secrets und Ableitung der Session Keys (HKDF).
    *   AES-CCM Verschlüsselung der Transport-Payloads.
2.  **Commissioning Abschließen**
    *   Implementierung der `HandleMessage` Logik für alle PASE-Schritte (Pake1, Pake2, Pake3).
    *   Verifizierung der Kryptografischen Proofs.
3.  **Session Management**
    *   Verwaltung von sicheren Sessions nach dem Handshake.
4.  **Application Layer**
    *   Implementation des Interaction Models (Read/Write/Invoke).
    *   Datenmodell für Cluster und Attribute.

## 🚀 Nutzung

### Voraussetzungen
*   Go 1.20 oder neuer

### Samples ausführen

Komiliere und starte das Device:
```bash
go run samples/commissioning/device/main.go
# Ausgabe: Device listening on 5540...
```

Starten den Controller (in einem neuen Terminal):
```bash
go run samples/commissioning/controller/main.go
# Ausgabe: Starting Matter Controller Sample...
# Ausgabe: Sending PBKDFParamRequest...
```

## 📂 Projektstruktur

*   `tlv/`: Encoder & Decoder für das Matter Binärformat.
*   `crypto/`: Wrapper für kryptografische Primitive (AES, HKDF, SPAKE2+).
*   `commissioning/`: Logik für das Pairing (PASE & CASE).
*   `transport/`: UDP Netzwerkkommunikation.
*   `samples/`: Ausführbare Beispielanwendungen.
*   `docs/`: Dokumentation und Diagramme (z.B. PASE Explainer).
*   `bin/`: Kompilierte Binaries (werden von git ignoriert).

