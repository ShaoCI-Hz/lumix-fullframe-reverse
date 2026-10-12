# Firmware Acquisition — Official Sources and Direct Links

> Conclusion first: **what Panasonic ships is a full firmware image (157 MB),
> not an incremental delta package.**
> The "only deltas are published" assumption has been disproven — no delta chain
> needs to be reconstructed, and no baseline has to be extracted from the camera.

---

## 1. Acquisition path (established)

Panasonic's main site has CDN anti-scraping for scripted requests, but the
**Japanese support site is directly reachable**. The full path:

```
https://panasonic.jp/dc/                                    <- entry point (200)
  → https://av.jpn.support.panasonic.com/support/dsc/download/top.html
  → ./index4.html        "デジタル一眼カメラ(フルサイズ)" full-frame model list
  → ff/dl/s5m2x.html     model download detail page
  → ff/dl/s5m2x_dl.html  download confirmation page (licence agreement)
  → direct file link
```

### Firmware direct link

```
https://panasonic.jp/support/share2/eww/com/dsc/ff/zip/S5m2XV27.zip
```

| Item | Value |
|---|---|
| Filename | `S5m2XV27.zip` |
| Size | 157,760,717 bytes (≈ 150.4 MiB) |
| Compression | ZIP |
| After extraction | `S5m2XV27.bin` |
| Platform | Windows / Mac, same file |
| Version | **Ver.2.7** |
| Released | 2026-03-10 |

The Referer must point at the download confirmation page or the request may be
rejected:
`https://av.jpn.support.panasonic.com/support/dsc/download/ff/dl/s5m2x_dl.html`

---

## 2. Request requirements (pitfalls encountered)

| Problem | Solution |
|---|---|
| `panasonic.com` returns 403 | Send full browser headers (UA/Accept/Sec-Fetch-*), or use `panasonic.jp` instead |
| `web_search` tool unusable | Its backend sat behind a dead proxy (`127.0.0.1:7897`); fetched pages directly with .NET instead |
| Python `urllib` connection refused | On Windows `urllib` reads proxy settings from the **registry**, unaffected by environment variables; use .NET `HttpWebRequest` and set `Proxy=$null` explicitly |
| Page text garbled | The page is **UTF-8**, not Shift-JIS |
| Search engines split the model name | Bing China turns `DC-S5M2X` into "DC comic"; following the official site navigation is more reliable |

**Standard approach**: .NET `HttpWebRequest` + `Proxy=$null` + full browser
headers + UTF-8 decoding.

---

## 3. Version history (as listed on the Ver.2.7 page)

| Date | Version | Highlights |
|---|---|---|
| 2026-03-10 | **2.7** | Support for the DMW-DMS1 microphone; LUMIX Flow (Ver.1.5+) support; stability improvements |
| 2025-12-23 | 2.6 | Fixed occasional corner artifacts when moving the camera with stabilisation on; fixed noise in recording on some SD cards |
| 2025-11-18 | 2.5 | Fixed recording stopping when the wireless connection dropped; fixed ring artifacts when detaching an APS-C lens without powering off |
| 2025-10-20 | 2.4 | DJI gimbal Bluetooth compatibility; OM flash compatibility; LUMIX Flow (Ver.1.3+) support; shutter-speed limiter; customisable focus-ring function |

> The page lists older versions too. **Historical versions are valuable for
> comparative firmware analysis** (they pin down exactly which bytes/functions a
> given feature change touched). It is worth downloading them as well: swap
> `S5m2XV27.zip` for the older filename on the same path.
> Older filenames can be parsed from each version's download confirmation page.

---

## 4. Sister model (for comparative analysis)

The same site publishes the full S5M2 firmware, useful for differential
comparison and for identifying model-specific code:

- `https://av.jpn.support.panasonic.com/support/dsc/download/ff/dl/s5m2.html`
- Filename of the form `S5m2V37.zip` → `S5m2V37.bin` (DC-S5M2 Ver.3.7, 2026-03-10)

> S5M2 and S5M2X share a very close hardware lineage, so a **binary comparison
> is the most efficient way to locate model-specific functionality** —
> the code differences behind features unique to the X variant (such as ProRes
> RAW / SS/RAW output) surface directly.

---

## 5. Paid features (explicitly out of scope)

The `ff/enhance/` path on the download site lists **paid feature upgrade packages**:

- `DMW-SFU2` — V-Log expansion for the DC-S5M2 (sold separately)
- `DMW-SFU3A` / `DMW-SFU1` — other models
- Activation entry point: `https://eww.pavc.panasonic.co.jp/enhance/ActivationTop/ja`

These are **paid licences**. This project **does not study or touch them** — an
entirely different matter from research into the firmware format.
