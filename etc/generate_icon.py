#!/usr/bin/env python3
"""Generate FreeGPGMail app icon with shield and envelope."""

from PIL import Image, ImageDraw


def generate_icon(size=4096):
    """Generate the icon at the given size (4096 for 2x supersample of 2048 canvas)."""
    scale = size / 2048.0

    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Background: #222222 with macOS 22% rounded corners
    bg_color = (0x22, 0x22, 0x22, 255)
    corner_radius = int(size * 0.22)
    draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=corner_radius, fill=bg_color)

    # Shield coordinates (scaled)
    # Top-left: (350, 230), Top-right: (1698, 230)
    # Sides go vertically down to y=1050
    # Bottom point: (1024, 1800)
    shield_points = [
        (350 * scale, 230 * scale),
        (1698 * scale, 230 * scale),
        (1698 * scale, 1050 * scale),
        (1024 * scale, 1800 * scale),
        (350 * scale, 1050 * scale),
    ]

    # Shield fill: #000000 (pure black)
    shield_fill = (0x00, 0x00, 0x00, 255)
    draw.polygon(shield_points, fill=shield_fill)

    # Shield border: #333333, ~3px (scaled)
    border_color = (0x33, 0x33, 0x33, 255)
    border_width = max(1, int(3 * scale))
    draw.line(shield_points + [shield_points[0]], fill=border_color, width=border_width, joint='miter')

    # Envelope: filled white rectangle, 680x460
    # Horizontally centered at x=1024
    # Vertically centered on FULL shield height (y=230 to y=1800)
    # Center y = (230 + 1800) / 2 = 1015
    env_w = 680 * scale
    env_h = 460 * scale
    env_cx = 1024 * scale
    env_cy = 1015 * scale

    env_left = env_cx - env_w / 2
    env_top = env_cy - env_h / 2
    env_right = env_cx + env_w / 2
    env_bottom = env_cy + env_h / 2

    # White envelope body
    draw.rectangle([env_left, env_top, env_right, env_bottom], fill=(255, 255, 255, 255))

    # V-flap lines: #222222, 5px thick
    flap_color = (0x22, 0x22, 0x22, 255)
    flap_width = max(1, int(5 * scale))

    # V-flap: from top-left and top-right corners to center, ~55% down
    flap_peak_y = env_top + env_h * 0.55

    draw.line([(env_left, env_top), (env_cx, flap_peak_y)], fill=flap_color, width=flap_width)
    draw.line([(env_cx, flap_peak_y), (env_right, env_top)], fill=flap_color, width=flap_width)

    return img


def main():
    output_dir = "/Users/alexereh/projects/personal/freegpgmail/FreeGPGMail/Assets.xcassets/AppIcon.appiconset"

    # Generate at 4096x4096 (2x supersample)
    print("Generating 4096x4096 supersampled icon...")
    img_4096 = generate_icon(4096)

    # Downscale to 2048 with LANCZOS
    print("Downscaling to 2048x2048...")
    img_2048 = img_4096.resize((2048, 2048), Image.LANCZOS)

    # All required sizes and filenames
    sizes = {
        "icon_1024.png": 1024,
        "icon_512@2x.png": 1024,
        "icon_512.png": 512,
        "icon_256@2x.png": 512,
        "icon_256.png": 256,
        "icon_128@2x.png": 256,
        "icon_128.png": 128,
        "icon_64@2x.png": 128,
        "icon_64.png": 64,
        "icon_32@2x.png": 64,
        "icon_32.png": 32,
        "icon_16@2x.png": 32,
        "icon_16.png": 16,
    }

    # Generate all sizes from 2048 master
    for filename, px in sizes.items():
        print(f"  {filename} ({px}x{px})")
        resized = img_2048.resize((px, px), Image.LANCZOS)
        resized.save(f"{output_dir}/{filename}", "PNG")

    print(f"\nDone! Saved {len(sizes)} icons to {output_dir}")


if __name__ == "__main__":
    main()
