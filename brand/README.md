# Cassava brand kit (platform use)

Extracted from the Cassava PowerPoint theme. Used by the operator console (`ui/console`),
the README demo media (`scripts/media`) and Grafana dashboards (`scripts/gen_dashboards.py`).

| Token | Hex | Use |
|---|---|---|
| Navy | `#001C57` | Top bar, dark grounds, headings on light |
| Ink | `#1E2A44` | Body text on light |
| Mint | `#00F19C` | Signal accent **on navy only** (fails contrast on white) |
| Mint deep | `#00B377` | Healthy state, chart series on light |
| Blue | `#0B3A8C` | Primary buttons, cards on navy |
| Link | `#1F4FBF` | Links |
| Slate / Mist / Cloud | `#5B6478` / `#C9D2E3` / `#EEF2F9` | Secondary text / borders / app background |

Type: **Montserrat** (theme major font — headings, numbers) bundled as WOFF2 under the SIL OFL
(`fonts/OFL-Montserrat.txt`); **Arial** (theme minor font — body).

Logos in `logo/`: `cassava-logo-white.png` on navy/dark, `cassava-logo-navy.png` on light,
`cassava-mark-*.png` (symbol only), `favicon-64.png`. Don't recolour, stretch or place the white
logo on light backgrounds. The Cassava name and logo are trademarks of Cassava Technologies.
