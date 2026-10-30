# Flet/Flutter vs Kivy on a Raspberry Pi Zero 2 W (HDMI)

Date: 2026-10-30. Status: audit, no code changed, nothing measured on a
device yet.
Scope: is Flet (Python on top of Flutter) a good UI stack for a Raspberry Pi
Zero 2 W driving an HDMI screen, in desktop or kiosk mode, compared with
Kivy, which the Witness Angel apps already use? Includes whether Flet can
run on the lightweight `flutter-pi` embedder.

All memory and timing figures below are order-of-magnitude **estimates**,
not measurements. Section 9 proposes the test that would replace them.
Flet facts were checked against `flet-dev/flet` at commit `d251ab4`
(2026-10-27, Flet 1.0.x, Flutter 3.44.8 pinned in `.fvmrc`).

## Summary

- **Lightest to heaviest:** Flutter on `flutter-pi` and Kivy are about
  equal; Flet is clearly heavier. The weight comes from Flet's extra layers
  (a second runtime, GTK, a display server), not from Flutter's rendering.
- **Desktop mode** (Raspberry Pi OS with Desktop + Flet) works but is the
  heaviest combination on 512 MB.
- **Kiosk mode with Flet:** run it under the `cage` Wayland kiosk
  compositor on Raspberry Pi OS Lite (section 5). That's the supported way
  to keep Flet's overhead low. One trap: `DISPLAY` must be set, or Flet
  silently switches to web-server mode.
- **Flet on `flutter-pi`** is possible but unsupported. It needs a small
  patch to Flet's Dart package, because Flet assumes "Linux" means a GTK
  window (section 7). It's the lightest way to run Flet, at a high
  maintenance cost.
- **Recommendation:** measure Kivy against Flet + `cage` on a real Zero 2
  first. Only consider `flutter-pi` if memory turns out to be too tight.

| | Kivy | Flet (GTK desktop) | Flet + `cage` | Flutter / Flet + `flutter-pi` |
|---|---|---|---|---|
| RAM at idle, app + stack (est.) | ~60-120 MB | ~270-450 MB incl. desktop | ~150-250 MB | ~100-190 MB |
| Needs X11/Wayland | no | yes | Wayland (`cage`) | no |
| Cold start on Zero 2 | slow (Python imports, ~5-15 s) | slow | slow | Flutter side fast (compiled ahead of time); Python side still slow with Flet |
| Language | Python | Python | Python | Dart (pure Flutter) or Python (Flet, patched) |
| Supported setup | yes | yes | yes | Flutter: yes; Flet: **no** |

Flet alone (Python server + GTK client) is estimated at ~120-200 MB; the
other Flet columns add the figures of section 4 to that.

## 1. Hardware limits

```
Pi Zero 2 W
+--------------------------------------------------+
| 4x Cortex-A53 @ 1 GHz  (roughly a Pi 3)          |
| 512 MB RAM, shared with the GPU    <-- main limit|
| VideoCore IV GPU, OpenGL ES 2.0 only (vc4 driver)|
| no Vulkan                                        |
+--------------------------------------------------+
```

RAM decides this, not CPU. A full desktop session (X11 or Wayland, a
window manager, GTK, panels) uses a large share of 512 MB before the app
starts.

## 2. How each stack is layered

```
KIVY                          FLET (desktop mode)              FLUTTER via flutter-pi
----                          -------------------              ----------------------
Python app                    Python app (Flet server)         Dart app (AOT compiled)
  |                             |  Unix socket / protocol        |
Kivy (Cython)                 Flutter client binary            flutter-pi embedder
  |                             |                                |
SDL2                          GTK3 embedder                    KMS/DRM + GLES2
  |                             |                              (no X, no Wayland)
KMS/DRM + GLES2               X11/Wayland + compositor
(no desktop needed)             |
                              GLES / Mesa
```

- **Kivy** draws directly through SDL2's kmsdrm backend: one Python
  process, no desktop.
- **Flet** runs Python plus a Flutter GTK client, which needs a display
  server. On Linux the two talk over a Unix domain socket
  (`messaging/flet_socket_server.py`). Packaging with `flet build linux`
  embeds Python inside the Flutter app (`serious_python`), making it one
  process, but it still uses the GTK embedder and still needs a desktop or
  compositor.
- **[`flutter-pi`](https://github.com/ardera/flutter-pi)** is a Flutter
  embedder that renders straight to KMS/DRM through EGL/GLES2, with no X11
  or Wayland. Its README lists the Pi Zero 2 (W) and the 512 MB Pi 2/3
  models as working (the original Pi Zero and Pi 1 are not).

## 3. Rendering risk on VideoCore IV

- **Flet's client (Flutter 3.44.8)** renders with Skia over OpenGL ES, the
  path that has worked on vc4 for years. Flutter's GTK embedder only knows
  two renderer types, `opengl` and `software`
  (`shell/platform/linux/fl_engine.cc`, env var `FLUTTER_LINUX_RENDERER`).
- **From Flutter 3.47, Impeller is the default renderer on Linux**, running
  on that same OpenGL ES path (the Linux embedder has no Vulkan path, so
  vc4's lack of Vulkan doesn't matter). Impeller's GLES backend was
  designed around GLES 2.0 limits, but I found no report of it on vc4. The
  opt-out, `fl_dart_project_set_enable_impeller(project, FALSE)` in the
  runner or the `--enable-impeller=false` engine switch, is announced as
  temporary. So when Flet moves to Flutter >= 3.47, re-test on the device.
- **`flutter-pi`** uses the engine's OpenGL ES 2 path; its `--vulkan` mode
  needs a Vulkan driver, which vc4 doesn't have.

If GL fails, `FLUTTER_LINUX_RENDERER=software` makes the GTK client run,
but a Zero 2 will struggle. Quick check either way: watch CPU use while a
list scrolls; one core pinned at 100% means software rendering.

## 4. Kiosk options with Flet

Flet can only make its own window fullscreen and frameless. Something else
must provide the display and start the app at boot.

```
 A) Full desktop + autostart     B) Bare X11 session        C) Wayland kiosk compositor
 ---------------------------     -------------------        ---------------------------
 Flet app (fullscreen)           Flet app (fullscreen)      Flet app (fullscreen)
 panel, file manager, ...        (no window manager)        cage (single-app, wlroots)
 labwc / openbox                 Xorg + xinit               DRM/KMS + HDMI
 Pi OS "with Desktop"            Pi OS Lite                 Pi OS Lite
 ~+150-250 MB                    ~+40-80 MB                 ~+20-40 MB
```

- **A, desktop mode:** Raspberry Pi OS with Desktop, plus a `.desktop`
  file in `~/.config/autostart/` (or an entry in labwc's `autostart`).
  Turn on zram swap (`apt install zram-tools`) and remove desktop extras
  you don't need.
- **B, bare X11:** autologin, then `startx` runs only the Flet app from
  `.xinitrc`. It works, but C is lighter and simpler.
- **C, `cage`:** recommended, see section 5.
- **Avoid:** Flet in web mode shown in `chromium --kiosk`. Chromium alone
  takes several hundred MB.

## 5. Kiosk setup with `cage` (recommended for Flet)

[`cage`](https://github.com/cage-kiosk/cage) is a Wayland compositor that
runs one app fullscreen. Debian ships it for arm64 (0.1.4 in bookworm,
0.2.0 in trixie), so it's an `apt install cage` away on Raspberry Pi OS,
and Flet's GTK client runs natively on Wayland.

**Trap:** Flet's `ft.run()` treats a missing `DISPLAY` variable as "headless
Linux server" (`utils/platform_utils.py`, `is_linux_server()`) and then
starts a web server instead of the desktop client, with no way to override
it. Debian's `cage` is built with XWayland support (`-Dxwayland=true`) and
exports `DISPLAY` to its child, but the package doesn't depend on
`xwayland`, so install it as well.

1. Raspberry Pi OS Lite, 64-bit. `apt install cage xwayland`.
2. Autologin on tty1: `raspi-config`, then System Options, Boot / Auto
   Login, Console Autologin.
3. Start `cage` from `~/.bash_profile`:
   ```bash
   if [ -z "$WAYLAND_DISPLAY" ] && [ "$(tty)" = /dev/tty1 ]; then
       exec cage -s -- /home/pi/app/venv/bin/python /home/pi/app/main.py
   fi
   ```
   `-s` ("allow VT switching") keeps Ctrl+Alt+F2 working, to reach another
   console for maintenance.
4. In the Flet app, as a safety net (`cage` already maximizes the window,
   but Flet's GTK runner draws a header bar on Wayland):
   ```python
   page.window.full_screen = True
   page.window.title_bar_hidden = True
   ```
   Both are fields of `controls/core/window.py` at `d251ab4`; older Flet
   versions used `page.window_full_screen`.

When the app exits, `cage` exits too. To restart the app automatically,
wrap the command in a `while true` loop, or use the systemd unit described
in `cage`'s README.

## 6. Flet-specific risks to check early

1. **Getting the arm64 client onto the Pi.** `pip install flet[desktop]`
   installs `flet-desktop`, a pure-Python wheel that downloads the Flutter
   client on first run from the GitHub release into `~/.flet/client/`.
   Release v1.0.5 does ship arm64 builds
   (`flet-linux-{debian10,debian12,ubuntu20.04,22.04,24.04}[-light]-arm64.tar.gz`);
   the distro is picked by glibc version (Pi OS bookworm, glibc 2.36, gets
   `debian12`) and the flavor defaults to `light` on Linux (what `light`
   leaves out is undocumented). **This requires 64-bit Raspberry Pi OS:**
   on a 32-bit OS, `platform.machine()` reports `armv7l`, which Flet maps
   to `arm_7`, and the release has no `arm_7` Linux client, so the
   download fails. So no build is needed, but the Pi needs
   network on first run, or pre-seed the cache (`FLET_VIEW_PATH` points at
   an unpacked client). `flet build linux` remains an option for a
   single-process package, on a bigger arm64 machine: the Flutter SDK
   can't realistically build on 512 MB.
2. **System libraries:** the client needs the GTK3 runtime, and GStreamer
   or `libmpv` only for audio/video controls (Flet's Linux packaging doc
   lists them). On Pi OS Lite they must be installed by hand.
3. **`DISPLAY` must be set:** see section 5.
4. **GPU vs software rendering:** see section 3.

## 7. Flet on `flutter-pi`

I found no public report of anyone doing this, so the findings below come
from reading Flet's Dart source (`flet-dev/flet` at `d251ab4`,
2026-10-27). Paths are relative to `packages/flet/lib/src/`.

### 7.1 Why it's possible

Flet's UI is a regular Dart package (`flet` on pub.dev) that renders
whatever a Python Flet server sends it over a socket. It already supports
these transports:

- `tcp://` and Unix sockets (`transport/flet_backend_channel_socket.dart:44`)
- `http(s)://`, using a WebSocket (`transport/flet_backend_channel.dart:70`)

`flutter-pi` runs any arm64 Flutter app compiled ahead of time. So you'd
write a small Flutter app that hosts Flet's widget, and launch it with
`flutter-pi`:

```
  Pi Zero 2 W, Raspberry Pi OS Lite, console only
  +-----------------------------------------------------------+
  |                                                           |
  |  python main.py  (Flet server, no window)                 |
  |      ^                                                    |
  |      | ws://127.0.0.1:8550  (or tcp://, see 7.4)          |
  |      v                                                    |
  |  flutter-pi  ./bundle                                     |
  |      +-- your main.dart:  FletApp(pageUrl: "http://...")  |
  |      +-- package:flet  (patched, see 7.2)                 |
  |      |                                                    |
  |  KMS/DRM + GLES2  -->  HDMI                               |
  +-----------------------------------------------------------+
```

### 7.2 What breaks: Flet assumes Linux means a GTK window

Flet decides it's on a desktop by checking whether the platform is Linux
(`utils/platform.dart:7`, `isDesktopPlatform()`). `flutter-pi` also
reports Linux, so Flet calls `window_manager`. That plugin is GTK code
loaded only by Flutter's standard Linux runner. `flutter-pi` doesn't load
it, so the calls fail with `MissingPluginException`.

| Code | When it runs | Effect on `flutter-pi` |
|---|---|---|
| `utils.dart:15`, `setupDesktop()` calls `windowManager.ensureInitialized()` | when the official client starts | Avoidable: your own `main.dart` needn't call it |
| `flet_backend.dart:511-512`, `updatePageSize()` calls `getWindowState()` | **on every page resize, including the first sizing** | **Blocks startup**, see below |
| `services/window.dart:76`, `WindowService.init()` | when the page's `window` control is created | Harmless: wrapped in `try/catch` |
| `utils/desktop.dart` (all window properties) | when Python sets `page.window.*` | Each call throws |

The startup block, traced through the source: `updatePageSize()` is an
`async void` method with no `try/catch`; its caller
(`widgets/page_media.dart:29-32`) doesn't catch either. So the exception
from `getWindowState()` becomes an unhandled async error and
`pageSizeUpdated.complete()` (line 520) never runs. `onRouteUpdated()`
(`flet_backend.dart:425`) awaits `pageSizeUpdated.future` before
registering the client with Python, so the page never registers and
nothing is drawn.

**Fix:** make `isDesktopPlatform()` return false, for example when an
environment variable like `FLET_NO_WINDOW_MANAGER` is set. Then the resize
code skips the window state, and `page.window.*` does nothing instead of
crashing (every function in `utils/desktop.dart` is already guarded by
`isDesktopPlatform()`).

This can't be done from outside Flet: Flutter's
`debugDefaultTargetPlatformOverride` is debug-only; its setter throws
"Cannot modify debugDefaultTargetPlatformOverride in non-debug builds",
and `flutter-pi` runs release bundles. That leaves two ways:

- a small fork of the `flet` package, pulled in through
  `dependency_overrides` in the host app
- contributing the option upstream to Flet. That's the better long-term
  route; otherwise the patch must be re-applied at every Flet upgrade.

### 7.3 Other native plugins

From the dependencies of `packages/flet/pubspec.yaml` and
`client/pubspec.yaml`. These only fail when the feature is actually used:

- **Breaks:** `url_launcher` (opening links), `pasteboard` (images on the
  clipboard), `file_picker` (GTK dialog), and `flet_video` / `flet_audio`,
  which use media_kit/libmpv. `flutter-pi` ships its own GStreamer-based
  players, but they implement different plugins.
- **Probably fine:** plugins whose Linux side is pure Dart:
  `path_provider`, `shared_preferences`, `device_info_plus`,
  `package_info_plus`.
- **Fine:** core controls (layout, text, buttons, lists), and keyboard and
  touch input, which `flutter-pi` handles.

### 7.4 Practical constraints

1. **Versions must match exactly.** The `flet` Dart package in the host app
   and the `flet` Python package on the Pi must be the same release; the
   protocol isn't stable across versions. Every Flet upgrade means
   rebuilding the bundle and re-applying the patch.
2. **Build on another machine.** Build the bundle with
   `flutterpi_tool build --arch=arm64 --release` on a Linux development
   PC (the tool needs Flutter SDK >= 3.10.5; use the Flutter version that
   release of Flet pins, 3.44.8 at `d251ab4`), then copy it to the Pi. It
   can't be built on the Pi itself. The README's `--cpu=pi4` tuning is for
   the Pi 4; the Zero 2 W is a Cortex-A53 like the Pi 3.
3. **Python side.** On a console-only Pi `DISPLAY` is unset, so `ft.run()`
   forces web-server mode (section 5): `ft.run(main, port=8550)` serves
   `http://127.0.0.1:8550` (default port 8000) and opens no browser. This
   needs `flet-web` (`pip install flet[web]`; Flet otherwise pip-installs
   it at first run) and its FastAPI/uvicorn stack. The lighter `tcp://`
   transport (`ft.run(main, view=None, port=8550)`) is only reachable with
   a dummy `DISPLAY` set, because of the same `is_linux_server()` check.
4. **Memory (estimate):** about 60-120 MB for `flutter-pi` plus 40-70 MB
   for the Python Flet server (more in web-server mode). That's comparable
   to Kivy, and much lighter than Flet with GTK, `cage` and a desktop.

### 7.5 Where it fits

```
                  setup effort      RAM        maintenance
Kivy direct       low               low        low (current stack)
Flet + cage       low-medium        medium     low (supported route)
Flet + flutter-pi medium-high       low        HIGH (fork, version pinning,
                                                    custom build)
```

It's only worth it if Flet's widgets are definitely wanted **and** the
memory saved over `cage` turns out to matter in a real test.

## 8. Fit with the Witness Angel codebase

- The Witness Angel apps are Kivy-based. Adopting Flet means a second UI
  stack to maintain. If the main appeal is nicer widgets, KivyMD may close
  enough of the gap.
- Pure Flutter on `flutter-pi` means Dart, which would need a bridge to the
  Python `wacryptolib` (a subprocess or a local socket).
- With Flet, the UI logic stays in Python and can call `wacryptolib`
  directly.

## 9. Proposed test on a real Zero 2

A one-hour test would replace the estimates above:

1. Flash Raspberry Pi OS Lite 64-bit and enable console autologin.
2. Write a hello-world in each stack (a page with a scrolling list and a
   button):
   - Kivy, drawing through SDL2 kmsdrm
   - Flet under `cage`
   - optionally, Flet on `flutter-pi` with the 7.2 patch
3. For each, measure:
   - total RSS with `smem -t`
   - free memory with `free -m` before and after starting the app
   - time from boot or launch to the first frame
   - CPU use while scrolling, to tell GPU from software rendering

## Sources

- [ardera/flutter-pi](https://github.com/ardera/flutter-pi)
- [cage-kiosk/cage](https://github.com/cage-kiosk/cage), [`cage` in Debian](https://packages.debian.org/bookworm/cage)
- [Infinum: Are Embedded Devices the Future of Flutter?](https://infinum.com/blog/flutter-embedded-device/)
- [meta-flutter flutter-pi recipe](https://layers.openembedded.org/layerindex/recipe/347428)
- [Flet `packages/flet/pubspec.yaml`](https://github.com/flet-dev/flet/blob/main/packages/flet/pubspec.yaml)
- [Flet `client/pubspec.yaml`](https://github.com/flet-dev/flet/blob/main/client/pubspec.yaml)
- [Flet `app.py`](https://github.com/flet-dev/flet/blob/main/sdk/python/packages/flet/src/flet/app.py), [`platform_utils.py`](https://github.com/flet-dev/flet/blob/main/sdk/python/packages/flet/src/flet/utils/platform_utils.py), [`flet_desktop/__init__.py`](https://github.com/flet-dev/flet/blob/main/sdk/python/packages/flet-desktop/src/flet_desktop/__init__.py)
- [Flet v1.0.5 release assets](https://github.com/flet-dev/flet/releases/tag/v1.0.5)
- [Flet: packaging for Linux](https://flet.dev/docs/publish/linux/)
- [Flutter: Impeller rendering engine](https://docs.flutter.dev/perf/impeller), [What's new in Flutter 3.47](https://flutter.dev/blog/whats-new-in-flutter-3-47)
- [Flutter Linux embedder `fl_engine.cc`](https://github.com/flutter/flutter/blob/master/engine/src/flutter/shell/platform/linux/fl_engine.cc)
- [Flutter `debugDefaultTargetPlatformOverride`](https://api.flutter.dev/flutter/foundation/debugDefaultTargetPlatformOverride.html)
