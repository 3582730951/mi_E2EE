# Repository Guidelines

## Project Structure & Module Organization
- Core C/C++ lives in `common/` (crypto, file ops, replay cache), `include/` (public headers), `mi_server/` (server + KCP relay + MySQL auth), and `mi_client_E2EE/` (client SDK, N-API bridge, Electron UI). Build artifacts stay in `build/`.
- Electron (Windows) sources: `mi_client_E2EE/src/E2EE_Client_Windows/` (`main.js`, `preload.js`, `src/index.html|css|js/`). Node addon sources under `mi_client_E2EE/mi_bridge/`.
- Specs and checklists: `protocol.md`, `EncryptedBasicTypes.md`, `Front-end_requirements.txt`, `integration_checklist.md`. Keep new docs beside these.

## Build, Test, and Development Commands
- Core libs/apps (OpenSSL+KCP+MySQL): `cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DMI_USE_OPENSSL=ON -DMI_USE_KCP=ON -DMI_USE_MYSQL=ON && cmake --build build`.
- Server app: after build, run `build/mi_server/mi_server_app` (reads `config.ini` beside the binary for MySQL host/port/user/pass/db).
- Node addon: `cd mi_client_E2EE/mi_bridge && npm install && npx node-gyp configure build`.
- Windows Electron shell: `cd mi_client_E2EE/src/E2EE_Client_Windows && npm install && npx electron .` (uses addon if present; otherwise mock data).
- Tests: configure with `-DBUILD_TESTING=ON` then `ctest --output-on-failure --test-dir build`.

## Coding Style & Naming Conventions
- C++17, 4-space indent, headers first. Exported APIs are `MI_*`; structs/classes PascalCase; fields lower_snake_case; local variables lowerCamelCase. Prefer RAII for buffers/sockets; zeroize plaintext via `MI_ErasePlain`.
- JS/Electron: lowerCamelCase functions, SCREAMING_SNAKE_CASE constants, kebab-case DOM IDs. Avoid logging plaintext or keys; keep encryption types (`EncString/EncJson/EncBytes`) at boundaries.
- Format with `clang-format` (Microsoft style) when available; `node-gyp` sources follow existing style.

## Testing Guidelines
- Cover AES-GCM, Ed25519 signing/verify, KCP paths, chunked file HMAC/ACK, replay window persistence, and MySQL auth in unit tests (`*_test.cpp`).
- UI/bridge: add smoke tests for `init/connect/login/sendMessage`, mock KCP raw send/receive, and ensure auto-ACK on receive paths.
- Keep fixtures deterministic; never store plaintext test payloads in repo history.

## Commit & Pull Request Guidelines
- Use Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`) with scoped modules (e.g., `feat(server): mysql auth`).
- PRs must include intent, test commands/results, and UI screenshots when touching `src/E2EE_Client_Windows`. Note optional flags used (KCP, MySQL, OpenSSL).
- Do not commit `build/`, `node_modules/`, binaries, secrets, or real certificates. Generate keys/certs in CI only.

## Security & Configuration Tips
- Default dev endpoint: `127.0.0.1:19999`; set server keys before traffic. Prefer OpenSSL on non-Windows; KCP is default when built.
- Replay cache persisted to `work_dir/replay.cache`; keep clocks in sync. Auto-ACK on receive clears queues; wipe temp files after transfers.
- MySQL config via `config.ini` beside server binary:
```
[mysql]
mysql_ip=127.0.0.1
mysql_port=3306
database=mie2ee
username=dbuser
passwd=dbpass
```
