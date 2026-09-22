# TechnitiumLibrary.Tests

This project contains the unit and integration-style test coverage for `TechnitiumLibrary.sln`.

The goal is to keep tests close to the module they cover, make socket-dependent behavior deterministic with local simulators, and steadily improve coverage without changing production implementation just to make tests easier.

## Running Tests

Run the full test project:

```powershell
dotnet test .\TechnitiumLibrary.Tests\TechnitiumLibrary.Tests.csproj
```

Run with coverage:

```powershell
dotnet test .\TechnitiumLibrary.Tests\TechnitiumLibrary.Tests.csproj --collect:"XPlat Code Coverage" -- DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Format=cobertura
```

Run from WSL/Ubuntu:

```bash
cd /mnt/d/AIProjects/DNS/TechnitiumLibrary
dotnet restore ./TechnitiumLibrary.Tests/TechnitiumLibrary.Tests.csproj
dotnet test ./TechnitiumLibrary.Tests/TechnitiumLibrary.Tests.csproj --no-restore
```

When switching between Windows and WSL, run `dotnet restore` in the OS you are about to test from. The generated NuGet assets can contain OS-specific package paths.

Run a module or class slice:

```powershell
dotnet test .\TechnitiumLibrary.Tests\TechnitiumLibrary.Tests.csproj --filter "FullyQualifiedName~TechnitiumLibrary.Net.Tor"
dotnet test .\TechnitiumLibrary.Tests\TechnitiumLibrary.Tests.csproj --filter "DnsDatagramTests"
```

## OS-Specific Tests

The test project should remain cross-OS by default. OS-specific tests are allowed only when the production API itself is platform-specific, and they must be guarded so the full test suite still passes on Windows, Linux, and macOS.

Current OS-specific tests:

```text
TechnitiumLibrary.Security.Cryptography/KeyAgreementTests.cs
  ECDiffieHellmanDerivesSameSecretOnSupportedPlatforms
  ECDiffieHellmanUnsupportedHashThrowsOnSupportedPlatforms
```

These tests exercise `TechnitiumLibrary.Security.Cryptography.ECDiffieHellman`, which uses `ECDiffieHellmanCng`. They run their assertions only on Windows and return immediately on non-Windows platforms.

Socket and protocol simulator tests are not considered OS-specific. They must continue to use loopback, ephemeral ports, and local simulators so they can run on all supported operating systems.

The full test project was verified on Ubuntu under WSL with .NET SDK `10.0.108`:

```text
Total tests: 356
Passed: 356
```

## Project Structure

Tests are grouped by the production assembly or module they cover:

```text
TechnitiumLibrary.Tests/
  TechnitiumLibrary/                         Core library tests
  TechnitiumLibrary.ByteTree/                ByteTree tests
  TechnitiumLibrary.IO/                      IO and stream/package tests
  TechnitiumLibrary.Net/                     Networking, DNS, HTTP, proxy, socket helpers
  TechnitiumLibrary.Net.BitTorrent/          BitTorrent protocol tests
  TechnitiumLibrary.Net.Mail/                Mail protocol tests
  TechnitiumLibrary.Net.Tor/                 Tor controller and hidden service tests
  TechnitiumLibrary.Net.UPnP/                UPnP tests
  TechnitiumLibrary.Security.Cryptography/   Cryptography tests
  TechnitiumLibrary.Security.OTP/            OTP tests
  Simulators/                                Local protocol/socket simulators used by tests
```

Nested folders should mirror the production module when useful. For example, DNS resource-record tests belong under:

```text
TechnitiumLibrary.Net/Dns/ResourceRecords/
```

## Contribution Guidelines

When adding tests:

- Keep production code unchanged unless a real production bug is discovered and explicitly being fixed.
- Put tests in the matching module folder. Avoid large catch-all test files for unrelated behavior.
- Prefer public APIs. Use reflection only when testing socket/protocol behavior would otherwise require unsafe or non-portable setup.
- Name tests by behavior, not implementation detail.
- Keep assertions meaningful. Avoid asserting incidental details such as object hash codes unless the hash behavior is the actual contract.
- Add focused tests first, then broaden only when the covered behavior is shared or high risk.
- All tests must run cross-OS. Avoid Windows-only commands, shell scripts, fixed ports, real network dependencies, or a real Tor/DNS/mail service.

## Simulator Guidelines

Socket-related tests should use local simulators instead of external services.

Simulator expectations:

- Place simulators under `Simulators/<module-name>/`.
- Bind to `IPAddress.Loopback` and an ephemeral port.
- Avoid fixed ports.
- Implement `IDisposable` and clean up listeners, sockets, streams, tasks, and cancellation tokens.
- Keep protocol behavior scriptable so tests can cover success, error, timeout, malformed, and disconnect scenarios.
- Prefer deterministic command/response queues over sleeps.
- Do not rely on internet access.
- Keep simulators small and protocol-specific.

Examples:

```text
Simulators/TechnitiumLibrary.Net/DnsTestServer.cs
Simulators/TechnitiumLibrary.Net.Mail/Pop3TestServer.cs
Simulators/TechnitiumLibrary.Net.Tor/TorControlTestServer.cs
```

## Coverage Work

Coverage improvements should be done module by module. A good coverage PR usually includes:

- New tests in the correct module folder.
- Simulator improvements when socket behavior is involved.
- A short note about coverage before and after, when coverage is the purpose of the change.
- A full `dotnet test` pass before submission.

High-value areas for future coverage include DNS parsing/serialization, DNS client behavior, proxy/socket flows, protocol simulators, and error handling paths.
