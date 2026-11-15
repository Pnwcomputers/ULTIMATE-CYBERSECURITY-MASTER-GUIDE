// =============================================================================
// mockups.scad — proxy ("stand-in") models of real hardware
// Load with:  use <lib/mockups.scad>
//
// A mockup is NOT a detailed CAD model. It is the smallest set of boxes and
// cylinders that captures what matters for fit: the outer envelope, the
// connectors, and the space a mating plug, cable or tool needs (keep-outs).
// Every number here is a starting point. Measure your own hardware.
// =============================================================================

use <utils.scad>

// -----------------------------------------------------------------------------
// LILYGO T-Embed CC1101 (body + dial + QWIIC socket)
// Frame: back face on z = 0, screen toward +Z, dial tip touching y = 0,
// long axis along +Y, centered on x = 0.
// Vendor envelope is 97.5 x 39 x 31 mm (overall maximum); measure your body.
// -----------------------------------------------------------------------------
module tembed_mock(L = 97.5, W = 38.5, D = 27.6,
                   dial_d = 32.5, dial_h = 2.5,
                   port_y = 30, port_z = 15, port_side = -1,
                   port_w = 4.6, port_h = 3.0) {
    // Body envelope
    color("Ivory", 0.55) difference() {
        slab(0, D) stadium(W, L);
        // QWIIC socket opening on the side wall
        translate([port_side * W / 2, port_y, port_z])
            cube([4, port_w, port_h], center = true);
    }
    // Rotary dial on the front face, centered on the rounded tip
    color("DimGray") translate([0, W / 2, D]) cylinder(d = dial_d, h = dial_h);
    // Screen area (visual reference only)
    color("SlateGray", 0.8) translate([-W / 2 + 6, W + 4, D - 0.2])
        cube([W - 12, 40, 0.3]);
}

// JST-SH (QWIIC) plug body sticking out of the device side.
// Frame: origin at the device side wall, plug grows along +X.
module qwiic_plug_mock(w = 6.0, len = 4.3, h = 3.0) {
    color("WhiteSmoke") translate([0, -w / 2, -h / 2]) cube([len, w, h]);
}

// -----------------------------------------------------------------------------
// GT-U7 GPS carrier board (u-blox 7 class receiver, u.FL/IPEX antenna jack)
// Frame: PCB centered on x/y, back face on z = 0, components hang toward -Z.
// Retail listings give about 27.6 x 26.6 mm; check your board's back side for
// parts (battery, LED) before choosing where the standoffs touch it.
// -----------------------------------------------------------------------------
module gtu7_mock(pcb = [26.6, 27.6, 1.6],
                 header_pins = 5, header_drop = 11, ufl_at = [10, 9.5]) {
    px = pcb[0]; py = pcb[1]; t = pcb[2];
    // PCB
    color("DarkGreen") translate([-px / 2, -py / 2, -t]) cube([px, py, t]);
    // Receiver module can (about 16 x 12.2 x 2.4 mm)
    color("Silver") translate([-8, -6.1 - 3, -t - 2.4]) cube([16, 12.2, 2.4]);
    // u.FL / IPEX jack
    color("Gold") translate([ufl_at[0], ufl_at[1], -t - 1.25])
        cylinder(d = 2.6, h = 1.25, $fn = 24);
    // Pin header along the +Y edge with a mated 1x5 Dupont housing below it
    hw = header_pins * 2.54;
    color("Black") translate([-hw / 2, py / 2 - 2.54, -t - header_drop])
        cube([hw, 2.54, header_drop]);
}

// u.FL position helper (matches gtu7_mock's ufl_at default)
function gtu7_ufl_offset() = [10, 9.5, -1.6 - 1.25];

// -----------------------------------------------------------------------------
// SMA rear-mount bulkhead jack (1/4-36 UNS thread, 8 mm hex nut)
// Frame: axis along +X (pointing out of the enclosure). x = 0 is the OUTER face
// of the panel, x = -panel_t the inner face.
// -----------------------------------------------------------------------------
module sma_bulkhead_mock(panel_t = 1.8, thread_len = 9.5, body_len = 6,
                         show_keepout = false, keepout_d = 11) {
    // Threaded barrel through the panel and out the front
    color("Gold") translate([-panel_t - 0.5, 0, 0]) rotate([0, 90, 0])
        cylinder(d = 6.35, h = thread_len + 0.5, $fn = 32);
    // Lock washer + nut on the outside
    color("Goldenrod") rotate([0, 90, 0]) cylinder(d = 10.2, h = 0.5, $fn = 32);
    color("Goldenrod") translate([0.5, 0, 0]) rotate([0, 90, 0])
        cylinder(d = 8 / cos(30), h = 2, $fn = 6);       // 8 mm across flats
    // Hex body / flange on the inside
    color("Goldenrod") translate([-panel_t - body_len, 0, 0]) rotate([0, 90, 0])
        cylinder(d = 8 / cos(30), h = body_len, $fn = 6);
    // Optional keep-out: space the inner hardware and your fingers need
    if (show_keepout)
        %translate([-panel_t - body_len - 2, 0, 0]) rotate([0, 90, 0])
            cylinder(d = keepout_d, h = body_len + 2, $fn = 32);
}

// Active GPS antenna on an SMA plug (puck), for preview only.
module gps_puck_mock() {
    color("DimGray") rotate([0, 90, 0]) cylinder(d = 8 / cos(30), h = 6, $fn = 6);
    color("Black") translate([6, -16, -6]) cube([14, 32, 12]);
}
