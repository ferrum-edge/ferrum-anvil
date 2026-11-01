// On-screen, normal-layer windows owned by one process, as JSON (macOS).
// Usage: osascript -l JavaScript mac-windows.js <pid>
// Reads the window server list (CGWindowListCopyWindowInfo); needs no
// Accessibility or Automation permission and sends no events to the app.
ObjC.import("CoreGraphics");

function run(argv) {
  const pid = Number(argv[0]);
  const kCGWindowListOptionOnScreenOnly = 1;
  const kCGNullWindowID = 0;
  const list = ObjC.deepUnwrap(ObjC.castRefToObject($.CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID))) || [];
  const mine = list.filter((w) => w.kCGWindowOwnerPID === pid && w.kCGWindowLayer === 0);
  return JSON.stringify(mine.map((w) => ({ owner: w.kCGWindowOwnerName, bounds: w.kCGWindowBounds, alpha: w.kCGWindowAlpha })));
}
