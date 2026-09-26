// Build Ferrum Anvil brand assets from the source logo with CoreGraphics.
//   swift brand.swift sample <src.png> x y          -> prints the RGB at (x, y)
//   swift brand.swift icon <src.png> <out.png> cx cy cw ch
//        crop (cx, cy, cw, ch) from the source (top-left origin) and place it in
//        a 1024x1024 rounded-square tile filled with the logo's background.
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

func load(_ path: String) -> CGImage {
    let src = CGImageSourceCreateWithURL(URL(fileURLWithPath: path) as CFURL, nil)!
    return CGImageSourceCreateImageAtIndex(src, 0, nil)!
}

func save(_ img: CGImage, _ path: String) {
    let dst = CGImageDestinationCreateWithURL(URL(fileURLWithPath: path) as CFURL, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(dst, img, nil)
    precondition(CGImageDestinationFinalize(dst), "could not write \(path)")
}

func rgba(_ w: Int, _ h: Int) -> CGContext {
    CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0,
              space: CGColorSpace(name: CGColorSpace.sRGB)!,
              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
}

/// Average colour of a small patch (top-left origin coordinates).
func sample(_ img: CGImage, _ x: Int, _ y: Int, _ r: Int = 6) -> (Double, Double, Double) {
    let ctx = rgba(img.width, img.height)
    ctx.draw(img, in: CGRect(x: 0, y: 0, width: img.width, height: img.height))
    let p = ctx.data!.bindMemory(to: UInt8.self, capacity: ctx.bytesPerRow * img.height)
    var s = (0.0, 0.0, 0.0), n = 0.0
    for yy in (y - r)...(y + r) {
        for xx in (x - r)...(x + r) {
            let row = img.height - 1 - yy // bitmap rows are bottom-up in CG space
            let o = row * ctx.bytesPerRow + xx * 4
            s.0 += Double(p[o]); s.1 += Double(p[o + 1]); s.2 += Double(p[o + 2]); n += 1
        }
    }
    return (s.0 / n / 255, s.1 / n / 255, s.2 / n / 255)
}

let a = CommandLine.arguments
switch a[1] {
case "sample":
    let c = sample(load(a[2]), Int(a[3])!, Int(a[4])!)
    print(String(format: "#%02x%02x%02x", Int(c.0 * 255), Int(c.1 * 255), Int(c.2 * 255)))
case "icon":
    let img = load(a[2])
    let (cx, cy, cw, ch) = (Int(a[4])!, Int(a[5])!, Int(a[6])!, Int(a[7])!)
    let crop = img.cropping(to: CGRect(x: cx, y: cy, width: cw, height: ch))!
    let bg = sample(img, cx + cw / 2, cy + 8, 4)
    let size = 1024
    let inset = a.count > 8 ? Double(a[8])! : 100.0, radius = a.count > 9 ? Double(a[9])! : 185.0
    let ctx = rgba(size, size)
    let tile = CGRect(x: inset, y: inset, width: Double(size) - 2 * inset, height: Double(size) - 2 * inset)
    ctx.addPath(CGPath(roundedRect: tile, cornerWidth: radius, cornerHeight: radius, transform: nil))
    ctx.clip()
    ctx.setFillColor(CGColor(srgbRed: bg.0, green: bg.1, blue: bg.2, alpha: 1))
    ctx.fill(tile)
    // Fit the crop to the tile width, centred vertically.
    let scale = tile.width / Double(cw)
    let dh = Double(ch) * scale
    let dest = CGRect(x: tile.minX, y: tile.midY - dh / 2, width: tile.width, height: dh)
    ctx.interpolationQuality = .high
    ctx.draw(crop, in: dest)
    // Fade the crop's top and bottom edges into the flat background.
    let fade = 70.0
    let cs = CGColorSpace(name: CGColorSpace.sRGB)!
    let solid = CGColor(srgbRed: bg.0, green: bg.1, blue: bg.2, alpha: 1)
    let clear = CGColor(srgbRed: bg.0, green: bg.1, blue: bg.2, alpha: 0)
    let g = CGGradient(colorsSpace: cs, colors: [solid, clear] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(g, start: CGPoint(x: 0, y: dest.maxY), end: CGPoint(x: 0, y: dest.maxY - fade), options: [])
    ctx.drawLinearGradient(g, start: CGPoint(x: 0, y: dest.minY), end: CGPoint(x: 0, y: dest.minY + fade), options: [])
    save(ctx.makeImage()!, a[3])
    print(String(format: "background #%02x%02x%02x", Int(bg.0 * 255), Int(bg.1 * 255), Int(bg.2 * 255)))
default:
    fatalError("unknown command \(a[1])")
}
