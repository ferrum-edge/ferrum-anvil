# Brand assets

| File | Used for | Source |
|---|---|---|
| `ferrum-anvil-logo.webp` | Lock screen (full logo with wordmark and tagline) | The Ferrum Anvil logo as supplied, unmodified |
| `ferrum-anvil-mark.png` | Top bar and empty workbench (160×160, full-bleed rounded tile) | Anvil emblem cropped from the logo |
| `../../src-tauri/icons/*` | Application icons (`.icns`, `.ico`, PNG sizes, store logos) | 1024×1024 rounded tile with macOS-style margins |

To regenerate the mark and icons from the logo, run this from `apps/desktop`
on macOS. `scripts/brand.swift` uses CoreGraphics and needs no extra tools.

```bash
sips -s format png src/assets/ferrum-anvil-logo.webp --out /tmp/logo.png
swift scripts/brand.swift icon /tmp/logo.png /tmp/icon-1024.png 330 150 820 570
swift scripts/brand.swift icon /tmp/logo.png /tmp/mark-1024.png 330 150 820 570 0 210
sips -z 160 160 /tmp/mark-1024.png --out src/assets/ferrum-anvil-mark.png
npx tauri icon /tmp/icon-1024.png -o /tmp/icons   # then copy the files that exist in src-tauri/icons
```

`330 150 820 570` crops the anvil emblem without the wordmark. The optional
last two arguments are the tile inset and corner radius (defaults 100 and
185); the mark uses `0 210` for a full-bleed tile.
