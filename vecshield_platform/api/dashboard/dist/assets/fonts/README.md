# Console fonts

The console sets its text in Inter and its identifiers, hashes and code in
JetBrains Mono. Both are self-hosted, because the console's Content Security
Policy allows only same-origin resources. Each file is a Latin subset of the
upstream variable font, cut to the 400–600 weight range the stylesheet uses.

| File | Source | Licence |
| --- | --- | --- |
| `inter-latin-var.woff2` | Inter 4.1, `InterVariable.ttf` from [rsms/inter v4.1](https://github.com/rsms/inter/releases/tag/v4.1) | SIL OFL 1.1, [`Inter-OFL.txt`](Inter-OFL.txt) |
| `jetbrains-mono-latin-var.woff2` | JetBrains Mono 2.304, `fonts/variable/JetBrainsMono[wght].ttf` from [JetBrains/JetBrainsMono v2.304](https://github.com/JetBrains/JetBrainsMono/releases/tag/v2.304) | SIL OFL 1.1, [`JetBrainsMono-OFL.txt`](JetBrainsMono-OFL.txt) |

Neither licence declares a Reserved Font Name, so the subsets keep the
upstream family names.

## Reproducing the subsets

Source checksums (SHA-256):

- `Inter-4.1.zip`: `9883fdd4a49d4fb66bd8177ba6625ef9a64aa45899767dde3d36aa425756b11e`
- `InterVariable.ttf`: `4989b125924991b90d05b2d16e0e388c48f7d5bb8b30539bbf9c755278d0ccaf`
- `JetBrainsMono-2.304.zip`: `6f6376c6ed2960ea8a963cd7387ec9d76e3f629125bc33d1fdcd7eb7012f7bbf`
- `JetBrainsMono[wght].ttf`: `662a196d58f1183bf2d77428b6d5283fe3f45161ab021bea4036bc98e5cac016`

With `fonttools==4.60.1` and `brotli` installed:

```sh
U="U+0000-017F,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-206F,U+2074,U+20AC,U+2122,U+2190-2199,U+21B5,U+2212,U+2215,U+2318,U+26A0,U+2713,U+2715"

python -m fontTools.varLib.instancer InterVariable.ttf wght=400:600 opsz=14 -o inter-i.ttf
python -m fontTools.subset inter-i.ttf --unicodes="$U" \
  --layout-features="kern,liga,calt,case,tnum,cv05,cv08,ccmp,locl,mark,mkmk" \
  --flavor=woff2 --output-file=inter-latin-var.woff2

python -m fontTools.varLib.instancer "JetBrainsMono[wght].ttf" wght=400:600 -o jbm-i.ttf
python -m fontTools.subset jbm-i.ttf --unicodes="$U" \
  --layout-features="kern,ccmp,locl,mark,mkmk,zero" \
  --flavor=woff2 --output-file=jetbrains-mono-latin-var.woff2
```

Characters outside the subset fall back, glyph by glyph, to the system fonts
named after the family in `--font-sans` and `--font-mono`. The size budget is
checked by `tests/fonts.test.mjs`.
