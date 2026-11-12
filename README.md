# BCS Reports Dashboard

A zoomable 3D dashboard over the BCS Reports Hub.

- **Main view:** one card per department with its report count and latest titles.
- **Zoom in** on a department (scroll, pinch, or click) to enter it and see its reports as a wall of live HTML screens.
- **Zoom in** on a report (or click it) to open it full size. **Zoom out** (or press Esc) to step back, all the way to the main view.

## Where the reports come from

This repo holds only the viewer. It reads the report feed from the Reports Hub published on the same GitHub Pages site (`../bcs-reports-hub/`), so new reports appear here as soon as the hub publishes them. The page checks for updates every five minutes and whenever the tab regains focus.

The hub's pages are encrypted with StatiCrypt. This page asks for the same password, decrypts in the browser, and stores nothing but the same "remember me" key the hub uses. No report content or password is kept in this repo.

To point the viewer at a different hub, change `data-hub` on the `<html>` tag in `index.html`.

## Files

- `index.html`, `styles.css`, `app.js` — the dashboard
- `three.module.min.js`, `CSS3DRenderer.js` — three.js r170 (MIT)
