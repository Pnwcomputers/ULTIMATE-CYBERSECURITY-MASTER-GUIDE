// =============================================================================
// utils.scad — small, reusable helpers for PNWC OpenSCAD projects
// Load with:  use <lib/utils.scad>
// Units: millimeters. No geometry is created when this file is `use`d.
// =============================================================================

// Extrude any 2D children into a slab that starts at height z and is h tall.
// Most parts in this repo are designed as 2D plans first, then "slabbed" up.
module slab(z, h) {
    translate([0, 0, z]) linear_extrude(height = h) children();
}

// 2D stadium (two semicircles joined by straight sides).
// Width w along X, length len along Y. The rounded tip touches y = 0.
module stadium(w, len) {
    hull() for (y = [w / 2, len - w / 2]) translate([0, y]) circle(d = w);
}

// A round tube that follows a list of 3D points. Each segment is the hull of
// two spheres, so corners are automatically rounded. Use for wires, coax,
// tubing and any "bendy" proxy.
module wire_path(points, d = 1, fn = 12) {
    for (i = [1 : len(points) - 1])
        hull() {
            translate(points[i - 1]) sphere(d = d, $fn = fn);
            translate(points[i])     sphere(d = d, $fn = fn);
        }
}

// A flat ribbon of n parallel wires. Every wire follows `points`, shifted by
// k * pitch along the `across` vector. Colors cycle through `colors`; the
// default order matches the Qwiic cable convention: GND, 3.3 V, SDA, SCL.
module ribbon(points, n = 4, pitch = 1.0, d = 0.9, across = [0, 1, 0],
              colors = ["black", "red", "blue", "yellow"]) {
    for (k = [0 : n - 1]) {
        shift = (k - (n - 1) / 2) * pitch * across;
        color(colors[k % len(colors)])
            wire_path([for (p = points) p + shift], d = d);
    }
}

// Keep only the part of the children where x >= x0 (a section / cutaway view).
// Size must be larger than the model.
module keep_x_above(x0 = 0, size = 400) {
    intersection() {
        children();
        translate([x0, -size / 2, -size / 2]) cube(size);
    }
}

// Rounded rectangle "slot" punched along the X axis through a wall.
// Centered on the origin: spans y in [-ly/2, ly/2], z in [-lz/2, lz/2].
module x_slot(ly, lz, depth, corner = 1.5) {
    c = min(corner, ly / 2 - 0.01, lz / 2 - 0.01);
    hull() for (y = [-ly / 2 + c, ly / 2 - c], z = [-lz / 2 + c, lz / 2 - c])
        translate([0, y, z]) rotate([0, 90, 0])
            cylinder(r = c, h = depth, center = true, $fn = 24);
}
