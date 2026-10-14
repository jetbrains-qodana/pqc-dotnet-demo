# PQC .NET Demo

Qodana for .NET includes inspections that flag cryptographic code that should be
migrated to post-quantum cryptography (PQC).

This project showcases the diverse means of how cryptography algorithms can be used in C#.
Running Qodana for .NET on it reveals which algorithms are vulnerable to quantum computers, requiring action by developers.

## References

- [Post-quantum cryptography (Wikipedia)](https://en.wikipedia.org/wiki/Post-quantum_cryptography)
- [NIST Post-Quantum Cryptography](https://www.nist.gov/pqc)

## Inspection levels

The inspections are grouped into five levels. Each level is cumulative — it includes
every level below it — and maps to a NIST PQC security level. Higher levels are
stricter and report more code.

| Level          | Meaning                                                                                    |
|----------------|--------------------------------------------------------------------------------------------|
| `PqcMinLevel1` | Flag pre-quantum and legacy cryptography. This uncovers the most critical vulnerabilities. |
| `PqcMinLevel2` | Flag baseline post-quantum algorithms. Includes PqcMinLevel1.                              |
| `PqcMinLevel3` | Flag standard-strength post-quantum algorithms. Includes PqcMinLevel1–2.                   |
| `PqcMinLevel4` | Flag high-strength post-quantum algorithms. Includes PqcMinLevel1–3.                       |
| `PqcMinLevel5` | Flag all algorithms except those providing maximum security. Includes PqcMinLevel1-4       |

## Configuration

One level is enabled at a time in [`qodana.yaml`](qodana.yaml). To switch levels,
change the `group` value to the level you want (`PqcMinLevel1` through
`PqcMinLevel5`):

```yaml
version: "1.0"
profile:
  name: qodana.recommended
  inspections:
    # Choose the PQC inspection level below. Each level is cumulative and includes
    # every level below it:
    #   PqcMinLevel1 – Flag pre-quantum and legacy cryptography. This uncovers the most critical vulnerabilities.
    #   PqcMinLevel2 – Flag baseline post-quantum algorithms. Includes PqcMinLevel1.
    #   PqcMinLevel3 – Flag standard-strength post-quantum algorithms. Includes PqcMinLevel1–2.
    #   PqcMinLevel4 – Flag high-strength post-quantum algorithms. Includes PqcMinLevel1–3.
    #   PqcMinLevel5 – Flag all algorithms except those providing maximum security. Includes PqcMinLevel1-4
    
    # e.g.
    # - group: PqcMinLevel5
    #   enabled: true

    # enable every PQC inspection. Also finds compliant algorithms
    - group: AllPqcInspections
      enabled: true
```

See https://www.jetbrains.com/help/qodana/post-quantum-cryptography.html#pqc-inspection-groups

## Running the analysis

Run the Qodana .NET linter with Docker from the project root:

```bash
docker run --rm -it \
    -p 8080:8080 \
    -e QODANA_TOKEN="$QODANA_TOKEN" \
    -v "$(pwd)":/data/project/ \
    -v "$(pwd)/.qodana/results":/data/results \
    jetbrains/qodana-dotnet:latest \
    --show-report
```

## Expected traces

File [`expected-traces/pqc-ground-truth.json`](expected-traces/pqc-dotnet-ground-truth.json) contains the
ground truth for the project.

The `expectedIssues` map is keyed by inspection id and each entry lists the file and the lines
that inspection should flag:

```json
"CsharpUsingCryptographyOidEd25519": [
  {
    "fileId": "PqcDotnetDemo/Classic/EllipticCurveHandshake.cs",
    "lines": [
      61,
      82
    ]
  }
]
```
