
# C++ Password Generator

A cryptographically secure command-line password generator written in modern C++.
All random choices are made with OpenSSL's `RAND_priv_bytes()` CSPRNG.

## Features

- Standard password — quick, strong, randomized password  
- Diceware passphrase — words from the 7,776-entry EFF Large Wordlist
- Complex memorable password — more secure, still user-friendly  
- Custom password builder — define length, character sets, patterns  
- Multiple passwords — generate many at once  
- Password strength check — heuristic feedback (not an entropy measurement)
- Quick generation — one-click generation  
- Generation by complexity level — pick desired strength or entropy

---

## Security properties

- No `rand()`, Mersenne Twister, or deterministic PRNG is used.
- Integer selection uses rejection sampling, avoiding modulo bias.
- Shuffling uses Fisher–Yates driven by the same CSPRNG.
- Diceware mode defaults to six words. The default 4–8 character filter leaves
  6,137 possible words, giving about 75.5 bits of word-selection entropy before
  optional suffixes. Using the complete list gives about 77.5 bits.
- On POSIX systems exported password files are created with mode `0600` and
  symbolic-link targets are rejected. Plain-text export is still optional and
  should be used with care.
- The strength checker is only a heuristic for user-supplied passwords; its label
  is not proof of cryptographic security.

## Usage

Run the executable after building:

```bash
./password_generator
````

---

## Building from Source

Clone the repository and build the project following the instructions for your platform.

<details>
<summary><strong>Linux / macOS</strong></summary>

```bash
# Clone the repo
git clone https://github.com/rafabduloff/cpp-pswd-gen.git
cd cpp-pswd-gen

# Dependencies (Debian/Ubuntu)
sudo apt install clang cmake make libssl-dev

# Build with CMake (uses clang++ by default)
cmake -S . -B build
cmake --build build

# Run
./build/cpp_pswd_gen

# Or build directly with Make
make
./pswd_gen
```

If you have multiple source files or use CMake, update these commands accordingly.

</details>

<details>
<summary><strong>Windows (PowerShell)</strong></summary>

---

## Windows Users

If you prefer not to build from source, you can download precompiled Windows binaries (`.exe`) from the [Releases](https://github.com/rafabduloff/cpp-pswd-gen/releases) page.
Just download the latest release, unzip if needed, and run the executable directly.

---

```powershell
# Clone the repo
git clone git@github.com:rafabduloff/cpp-pswd-gen.git
cd cpp-pswd-gen

# Build with MSVC (Visual Studio Developer Command Prompt)
cmake -S . -B build
cmake --build build --config Release

# Run
.\build\Release\cpp_pswd_gen.exe
```

OpenSSL development libraries must be discoverable by CMake (for example via
vcpkg or a standard OpenSSL installation).

</details>

---

## Screenshot

![Menu](menu.png)

---

## Diceware data

`data/eff_large_wordlist.txt` is the
[EFF Large Wordlist for Passphrases](https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt)
(7,776 entries). EFF recommends at least six words from its long list. EFF site
content is published under [CC BY 3.0 US](https://www.eff.org/copyright).
