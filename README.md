# Trading Bot Safety Guard

Defensive GitHub Action for auditing trading-bot repositories before deployment. It detects common publication and configuration risks without connecting to an exchange or accessing an account.

## Checks

- Tracked `.env` files and credential-like values.
- Private-key material.
- Live Binance, Bybit, or BingX endpoints without a demo/testnet alternative in the same client.
- Configured leverage above a policy limit.
- Redacted annotations and a Markdown job summary.

The action never prints detected credential values and uses only the Python standard library.

## Usage

```yaml
name: Trading bot safety

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Lucioelpro22/trading-bot-safety-guard@v1
        with:
          path: .
          fail-on-secrets: "true"
          require-demo: "true"
          max-leverage: "5"
```

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `path` | `.` | Directory to scan. |
| `fail-on-secrets` | `true` | Fail on credential-like material. |
| `require-demo` | `true` | Require demo/testnet evidence when exchange endpoints appear. |
| `max-leverage` | `5` | Highest permitted configured leverage. |

## Outputs

| Output | Description |
| --- | --- |
| `findings` | Total number of findings. |
| `report` | Path to the Markdown report generated on the runner. |

## Scope and limitations

This is a defensive static check. It does not prove that a bot is secure, profitable, compliant, or safe to operate. It does not validate strategy quality, exchange behavior, slippage, funding, liquidity, or financial risk.

## Development

```bash
python -m unittest discover -s tests -v
```

## License

MIT
