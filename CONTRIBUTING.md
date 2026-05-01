# Contributing to Asterion Network Security Auditor

Thank you for your interest in contributing to **Asterion**! This project is part of the Argos Security Suite, and we welcome contributions from the security community.

---

## 🤝 Code of Conduct

By participating in this project, you agree to:

- **Be respectful**: Treat all contributors with respect and professionalism
- **Be ethical**: Only contribute security checks that follow ethical hacking principles
- **Be transparent**: Clearly document any changes to security checks or scanning behavior

---

## 🎯 How Can You Contribute?

### 1. **Report Bugs**

Found a bug? Please open an issue with:

- **Description**: Clear explanation of the problem
- **Reproduction steps**: How to reproduce the issue
- **Environment**: OS, .NET version, Docker version (if applicable)
- **Expected vs Actual behavior**
- **Logs**: Include relevant error messages or stack traces

**Template:**

```
**Bug Description:**
[Brief description]

**To Reproduce:**
1. Run command: `ast scan --target ...`
2. Observe behavior: [what happened]

**Expected:** [what should happen]

**Environment:**
- OS: [e.g., Kali Linux 2024.1, Windows 11]
- .NET Version: [run `dotnet --version`]
- Asterion Version: [e.g., v0.2.0]

**Logs:**
```

[paste relevant logs]

```

```

---

### 2. **Suggest Features or New Checks**

We're always looking for new security checks! To suggest one:

1. **Check the [ROADMAP.md](docs/ROADMAP.md)** to see if it's already planned
2. **Open an issue** with the `enhancement` label
3. **Provide details**:
    - What vulnerability/misconfiguration does it detect?
    - Why is it important for network security?
    - What protocols/services does it target?
    - How should it be detected (passive vs aggressive)?

**Example:**

```
**Check Name:** AST-SSH-004 - Weak SSH Key Exchange Algorithms

**Description:** Detect SSH servers allowing weak key exchange algorithms (diffie-hellman-group1-sha1)

**Severity:** Medium

**Protocol:** SSH (TCP/22)

**Detection Method:**
- Connect to SSH server
- Parse server banner and key exchange offer
- Check for weak algorithms in KEX list

**Remediation:**
Add to /etc/ssh/sshd_config:
KexAlgorithms curve25519-sha256,ecdh-sha2-nistp521,...

**References:**
- [Mozilla SSH Guidelines](https://infosec.mozilla.org/guidelines/openssh)
```

---

### 3. **Submit Code Contributions**

#### Prerequisites

Before contributing code:

1. **Read the documentation**:
    - [README.md](README.md) - Project overview
    - [ETHICS.md](docs/ETHICS.md) - Ethical guidelines
    - [NETWORK_CHECKS.md](docs/NETWORK_CHECKS.md) - Check structure

2. **Set up your development environment**:

    ```bash
    # Clone the repository
    git clone https://github.com/rodhnin/asterion-network-minotaur.git
    cd asterion-network-minotaur

    # Install .NET 8.0 SDK
    # https://dotnet.microsoft.com/download/dotnet/8.0

    # Build the project
    dotnet build src/Asterion.sln

    # Run tests (if available)
    dotnet test
    ```

3. **Understand the project structure**:
    ```
    src/Asterion/
    ├── Checks/              # Security checks organized by protocol
    │   ├── CrossPlatform/   # Windows + Linux checks
    │   ├── Windows/         # Windows-specific checks
    │   └── Linux/           # Linux-specific checks
    ├── Core/                # Core engine (Config, Scanner, Reports)
    └── Cli.cs               # Command-line interface
    ```

---

#### Development Workflow

1. **Fork the repository** on GitHub

2. **Create a feature branch**:

    ```bash
    git checkout -b feature/ast-protocol-check-name
    # Example: feature/ast-ssh-004-weak-kex
    ```

3. **Write your code**:
    - Follow C# coding conventions (see below)
    - Add XML documentation comments to public methods
    - Implement proper error handling
    - Use structured logging (Serilog)

4. **Test your changes**:

    ```bash
    # Build and test locally
    dotnet build
    ./scripts/setup.py  # Install locally
    ast scan --target <test-target>
    ```

5. **Commit with clear messages**:

    ```bash
    git commit -m "feat: add AST-SSH-004 weak KEX algorithm detection"
    ```

    **Commit message format:**
    - `feat:` - New feature/check
    - `fix:` - Bug fix
    - `docs:` - Documentation changes
    - `refactor:` - Code refactoring
    - `test:` - Test additions/changes

6. **Push and create a Pull Request**:

    ```bash
    git push origin feature/ast-ssh-004-weak-kex
    ```

    Then open a PR on GitHub with:
    - **Clear title**: `feat: AST-SSH-004 - Weak SSH Key Exchange Detection`
    - **Description**: What does this PR add/fix?
    - **Testing**: How did you test it?
    - **Screenshots**: Include terminal output or reports if applicable

---

#### Code Style Guidelines

**C# Conventions:**

- Use **PascalCase** for classes, methods, properties
- Use **camelCase** for local variables
- Use **UPPER_SNAKE_CASE** for constants
- Add XML doc comments to public APIs:
    ```csharp
    /// <summary>
    /// Detects weak SSH key exchange algorithms.
    /// </summary>
    /// <param name="target">Target host to scan</param>
    /// <returns>List of findings</returns>
    public async Task<List<Finding>> CheckWeakKex(string target)
    ```

**Security Check Structure:**

```csharp
namespace Asterion.Checks.CrossPlatform;

public class SshWeakKexCheck : ISecurityCheck
{
    public string CheckId => "AST-SSH-004";
    public string Name => "Weak SSH Key Exchange Algorithms";
    public Severity DefaultSeverity => Severity.Medium;

    public async Task<List<Finding>> ExecuteAsync(ScanTarget target, Config config)
    {
        var findings = new List<Finding>();

        // 1. Connect to service
        // 2. Perform check
        // 3. Create finding if vulnerable
        // 4. Return results

        return findings;
    }
}
```

**Logging:**

```csharp
using Serilog;

Log.Debug("Connecting to SSH server at {Host}:{Port}", host, port);
Log.Information("Found weak KEX algorithm: {Algorithm}", weakAlgo);
Log.Warning("SSH connection failed: {Error}", ex.Message);
```

---

### 4. **Improve Documentation**

Documentation contributions are highly valued! You can:

- Fix typos or unclear explanations
- Add examples or use cases
- Improve installation instructions
- Add translations (future)
- Create tutorials or blog posts (link them in issues!)

**Documentation files:**

- `README.md` - Main project documentation
- `docs/NETWORK_CHECKS.md` - Security checks reference
- `docs/AI_INTEGRATION.md` - AI analysis guide
- `docs/DATABASE_GUIDE.md` - Database schema
- `docs/ETHICS.md` - Ethical guidelines
- `docker/README.md` - Docker deployment

---

### 5. **Add Demo Content**

We need visual content! Contribute:

- **Demo GIF/video**: Record Asterion scanning a vulnerable lab (30-60 seconds)
- **Screenshots**: HTML report examples, terminal output, findings tables
- **Tutorial videos**: Installation, first scan, Docker deployment

**Where to add:**

- Place media files in `assets/` directory
- Update README.md sections:
    - `## 🎬 Demo` - Add demo GIF/video
    - `## 📸 Screenshots` - Add report screenshots

**Requirements:**

- Use a **safe test environment** (VulnHub VMs, HackTheBox, your own lab)
- **Blur/redact** any sensitive information (real IPs, domains, credentials)
- Use **high-quality** screenshots (PNG format, 1920x1080 or higher)
- Add **captions** explaining what's shown

---

## 🔬 Testing Guidelines

### Setting Up a Test Environment

**Option 1: Docker Vulnerable Lab**

```bash
cd docker
docker compose -f compose.testing.yml up -d
ast scan --target 172.20.0.0/24  # Scan lab network
```

**Option 2: Local VMs**

- Use VirtualBox/VMware with vulnerable VMs
- Popular options: Metasploitable, VulnHub VMs, DVWA

**Option 3: Cloud Test Lab**

- Deploy test infrastructure in AWS/Azure/GCP
- **IMPORTANT**: Ensure it's isolated and properly configured for testing

### What to Test

Before submitting a PR, verify:

1. **Functionality**: Does the check detect the vulnerability?
2. **False Positives**: Does it correctly ignore secure configurations?
3. **Performance**: Does it complete in reasonable time?
4. **Error Handling**: Does it gracefully handle connection failures?
5. **Logging**: Are debug/info logs helpful for troubleshooting?
6. **Reports**: Do findings appear correctly in JSON/HTML reports?

---

## 🐛 Security Vulnerability Disclosure

**DO NOT** open public issues for security vulnerabilities!

Contact me on [https://rodhnin.com](https://rodhnin.com).

---

## 📋 Pull Request Checklist

Before submitting your PR, ensure:

- [ ] Code builds without errors (`dotnet build`)
- [ ] New checks include XML documentation
- [ ] Check ID follows convention (`AST-XXX-###`)
- [ ] Severity levels are appropriate (Critical/High/Medium/Low/Info)
- [ ] Remediation guidance is clear and actionable
- [ ] Changes are tested against real vulnerable/secure targets
- [ ] Commit messages follow convention (`feat:`, `fix:`, etc.)
- [ ] PR description explains what/why/how
- [ ] No sensitive data in code/logs/screenshots

---

## 🎓 Learning Resources

New to C# or network security? Here are helpful resources:

**C# / .NET:**

- [Microsoft C# Documentation](https://learn.microsoft.com/en-us/dotnet/csharp/)
- [.NET 8.0 API Reference](https://learn.microsoft.com/en-us/dotnet/api/)

**Network Security:**

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

**Ethical Hacking:**

- [SANS Penetration Testing](https://www.sans.org/cyber-security-courses/penetration-testing-ethical-hacking/)
- [Hack The Box Academy](https://academy.hackthebox.com/)

---

## 📞 Questions?

- **General questions**: Open a GitHub Discussion
- **Bug reports**: Open a GitHub Issue
- **Project maintainer**: [rodhnin](https://github.com/rodhnin) | [https://rodhnin.com](https://rodhnin.com)

---

## 📜 License

By contributing to Asterion, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

**Thank you for helping make network security auditing more accessible!** 🛡️

Part of the **Argos Security Suite**:

- 👁️ [Argus](https://github.com/rodhnin/argus-wp-watcher) - WordPress Security Scanner
- 🔥 [Hephaestus](https://github.com/rodhnin/hephaestus-server-forger) - Vulnerability Server Scanner
- 🔮 [Pythia](https://github.com/rodhnin/pythia-sql-clairvoyance) - SQL Injection Detection Scanner
- 🐂 **Asterion** - Network Security Auditor (this project)
