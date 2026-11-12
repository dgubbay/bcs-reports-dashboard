# BCS Reports Dashboard

A zoomable 3D dashboard over the BCS reports feed.

- **Main view:** one card per department with its report count and latest titles.
- **Zoom in** on a department (scroll, pinch, or click) to enter it and see its reports as a wall of live HTML screens.
- **Zoom in** on a report (or click it) to open it full size. **Zoom out** (or press Esc) to step back, all the way to the main view.

## Where the reports come from

Encrypted daily reports are published into the `data/` folder of this repo: an encrypted feed at `data/index.html`, plus encrypted report files. The viewer reads that feed via `data-hub="./data/"` on the `<html>` tag. New reports appear after the weekday publish, and the page also checks for updates every five minutes and whenever the tab regains focus.

The files in `data/` are encrypted with StatiCrypt. This page asks for the password, decrypts in the browser, and stores nothing but the same "remember me" key. No report content or password is kept in this repo in plaintext.

To point the viewer at a different feed, change `data-hub` on the `<html>` tag in `index.html`.

## Files

- `index.html`, `styles.css`, `app.js` — the dashboard
- `three.module.min.js`, `CSS3DRenderer.js` — three.js r170 (MIT)
- `data/` — encrypted report feed (written by the daily publisher)
