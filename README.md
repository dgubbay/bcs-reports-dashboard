# BCS Reports Dashboard

A zoomable 3D dashboard over the BCS reports feed.

- **Main view:** one card per department with its report count and latest titles, plus a live **Outbound** card for the TV board.
- **Zoom in** on a department (scroll, pinch, or click) to enter it and see its reports as a wall of live HTML screens.
- **Outbound room:** each board panel (this week, 30 days, leads, meetings, and so on) is a static live screen on a wall in front of you. Scroll, pinch, or use +/− to zoom toward a screen; zoom out or press Esc to step back. Clicking a screen does nothing. On a phone the screens stack in a one- or two-column wall you can drag through; pinch zooms toward the pinch point, and there is still no tap-to-open.
- **Mobile:** the dashboard is laid out for phones (portrait and landscape) and tablets. The top bar keeps Refresh and Lock on one row, the password gate respects safe-area insets, and the 3D view uses the dynamic viewport height so iOS Safari’s toolbar does not clip it.
- **Zoom in** on a report (or click it) to open it full size. **Zoom out** (or press Esc) to step back, all the way to the main view.

## Where the reports come from

Encrypted daily reports are published into the `data/` folder of this repo: an encrypted feed at `data/index.html`, plus encrypted report files. The viewer reads that feed via `data-hub="./data/"` on the `<html>` tag. New reports appear after the weekday publish, and the page also checks for updates every five minutes and whenever the tab regains focus.

The files in `data/` are encrypted with StatiCrypt. This page asks for the password, decrypts in the browser, and stores nothing but the same "remember me" key. No report content or password is kept in this repo in plaintext.

The Outbound room is an exception: it reads the already-public [BCS outbound board](https://dgubbay.github.io/bcs-outbound-board/) directly, shows each of its slides as a static panel, and refreshes them on the same five-minute cadence as the report feed. That board is not encrypted.

To point the viewer at a different feed, change `data-hub` on the `<html>` tag in `index.html`.

## Files

- `index.html`, `styles.css`, `app.js` — the dashboard
- `three.module.min.js`, `CSS3DRenderer.js` — three.js r170 (MIT)
- `data/` — encrypted report feed (written by the daily publisher)
