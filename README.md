# Go-Matter SDK

This project is an implementation of the Matter Smart Home Protocol Standard in Go.
The goal is to create a functional, understandable, and modular SDK that covers both the Device side (Accessories) and the Controller side (Commissioners/Fabric Admins).

The project is currently in the **Scaffolding / Prototyping Phase**.

## 🏗 Project Status

### ✅ Implemented

*   **TLV (Tag-Length-Value)**
    *   Complete `Encoder` and `Decoder` for Matter-compliant TLV.
    *   Support for basic types, containers (Structs, Arrays, Lists), and `omitempty`.
    *   Unit tests and loopback verification.
*   **Transport Layer (Basis)**
    *   Basic UDP framework (`TransportManager`).
    *   Sending and receiving messages via callback handlers.
*   **Commissioning (PASE - Passcode Authenticated Session Establishment)**
    *   Skeleton for the PASE State Machine.
    *   Data Structs for `PBKDFParamRequest` and `PBKDFParamResponse` with TLV tags.
    *   Logic for exchanging the initial handshake messages.
*   **Samples**
    *   `samples/commissioning/device`: A sample device listening on UDP and answering PASE requests (Stub).
    *   `samples/commissioning/controller`: A sample controller initiating the handshake.

### 🚧 In Progress / Planned

1.  **Complete Cryptography**
    *   Full integration of **SPAKE2+** (via `crypto` package).
    *   Calculation of Shared Secrets and derivation of Session Keys (HKDF).
    *   AES-CCM encryption of transport payloads.
2.  **Finish Commissioning**
    *   Implementation of `HandleMessage` logic for all PASE steps (Pake1, Pake2, Pake3).
    *   Verification of cryptographic proofs.
3.  **Session Management**
    *   Management of secure sessions after the handshake.
4.  **Application Layer**
    *   Implementation of the Interaction Model (Read/Write/Invoke).
    *   Data model for Clusters and Attributes.

## 🚀 Usage

### Prerequisites
*   Go 1.20 or newer

### Running the Samples

Compile and start the Device:
```bash
go run samples/commissioning/device/main.go
# Output: Device listening on 5540...
```

Start the Controller (in a new terminal):
```bash
go run samples/commissioning/controller/main.go
# Output: Starting Matter Controller Sample...
# Output: Sending PBKDFParamRequest...
```

## 📂 Project Structure

*   `tlv/`: Encoder & Decoder for the Matter binary format.
*   `crypto/`: Wrapper for cryptographic primitives (AES, HKDF, SPAKE2+).
*   `commissioning/`: Logic for pairing (PASE & CASE).
*   `transport/`: UDP network communication.
*   `samples/`: Executable sample applications.
*   `docs/`: Documentation and diagrams (e.g., PASE Explainer).
*   `bin/`: Compiled binaries (ignored by git).

## 📚 Documentation

*   [PASE Protocol Explanation](docs/PASE_Explainer.md): An in-depth look at the initial handshake protocol.
