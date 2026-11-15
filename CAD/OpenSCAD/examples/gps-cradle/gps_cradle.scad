// =============================================================================
// gps_cradle.scad — LILYGO T-Embed CC1101 sleeve with a GT-U7 GPS pod
// Tutorial example for CAD/OpenSCAD/04-tutorial-gps-cradle.md
//
// Coordinate system (millimeters):
//   +Y  long axis of the handset; the dial tip touches y = 0
//   +Z  out of the screen; the handset's back face sits on z = 0
//   -Z  the GPS pod hangs behind the handset, closed by a snap-on lid
//   X   centered; port_side = -1 puts the QWIIC cable on the left (-X)
//
// Parts (Customizer "part" dropdown):
//   preview  assembly with ghosted hardware, exploded lid
//   body     printable sleeve + pod (stood on its open end for printing)
//   lid      printable lid with snap tabs (flat, outside face down)
//   inlay    optional second-color circuit traces for the lid
//   gauge    8 mm slice of the body (fit_gap, lip, SMA hole): a quick test print
//   sma_gauge  coupon with five SMA hole sizes to find your best sma_hole_d
//   mockups  hardware proxies only
//   clash    overlap between printed parts and hardware (should be EMPTY)
//   clash_view  same overlap drawn in red inside a ghosted assembly
//   section  cut-away view at x = section_x
// =============================================================================

use <lib/utils.scad>
use <lib/mockups.scad>
use <lib/snapfit.scad>

/* [Render] */
part = "preview"; // [preview, body, lid, inlay, gauge, sma_gauge, mockups, clash, clash_view, section]
show_mockups = true;
show_cable = true;
lid_explode = 15;   // [0:1:40]
section_x = 0;      // [-30:0.5:30]

/* [Handset: LILYGO T-Embed CC1101 - measure yours] */
dev_length = 97.5;  // tip of dial end to far end
dev_width  = 38.5;  // across the straight sides
dev_depth  = 27.6;  // back to front rim (dial not included)
dial_d     = 32.5;
dial_h     = 2.5;
port_y     = 30;    // QWIIC socket center, measured from the dial tip
port_z     = 15;    // QWIIC socket center, measured up from the back
port_side  = -1;    // [-1:left, 1:right]

/* [Fit & Walls] */
fit_gap   = 0.30;   // clearance per side between handset and sleeve
wall      = 1.8;    // back plate and pod walls (4 x 0.45 mm lines)
arm_wall  = 4.5;    // sleeve side thickness
front_lip = 2.2;    // how far the lip reaches over the screen bezel
lip_t     = 2.0;    // lip thickness

/* [Sleeve & Port Window] */
sleeve_len = 58;    // how much of the handset the sleeve covers
win_y0     = 22;    // window start along Y
win_y1     = 42;    // window end along Y
win_h      = 13;    // window height (Z)
cable_groove = true;
groove_w   = 5.0;
groove_d   = 1.0;

/* [GPS Pod & Board] */
pod_depth   = 22;   // inside depth of the pod (behind the back plate)
pcb_w       = 26.6; // GT-U7 board, X
pcb_l       = 27.6; // GT-U7 board, Y
pcb_t       = 1.6;
pcb_y0      = 7;    // board edge nearest the dial tip
standoff_h  = 4;    // gap between back plate and board back face
pcb_gap     = 0.30; // board edge to latch arm
pcb_hook    = 0.40; // hook overlap onto the board
pcb_play    = 0.20; // vertical slack under the hook
latch_t     = 1.2;
latch_len   = 8;
header_drop = 11;   // header + mated Dupont housing below the board

/* [SMA Bulkhead] */
sma_hole_d   = 6.6;  // 6.35 mm thread + clearance; tune with the gauge
sma_flat     = 5.9;  // D-flat width, 0 = plain round hole
sma_y        = 46;
sma_side     = 1;    // [-1:left, 1:right]
sma_keepout  = 11;   // inner nut/flange + wrench clearance

/* [Cable Entry] */
notch_w = 6;
notch_h = 5;

/* [Lid & Snap Tabs] */
lid_t        = 1.6;
lid_chamfer  = 0.6;
tab_w        = 5;
tab_t        = 1.2;
tab_len      = 7;
snap_gap     = 0.25;  // tab face to wall face
snap_engage  = 0.60;  // how far the tooth reaches into its recess
far_tab_x    = 10;
max_strain   = 0.03;  // snap design limit: ~0.03 PETG/ASA; PLA ~0.015-0.025

/* [Two-Color Inlay] */
trace_w = 0.9;   // 2 x 0.45 mm lines
trace_d = 0.4;   // 2 x 0.20 mm layers

/* [Test Coupons] */
gauge_y = 42.5;  // slice start: past the port window, includes the SMA hole
gauge_len = 8;
sma_test_d = [6.4, 6.5, 6.6, 6.7, 6.8];

/* [Hidden] */
$fn = 64;
eps = 0.01;

// ---------------------------------------------------------------- derived ---
r      = dev_width / 2;
in_r   = r + fit_gap;                 // sleeve bore half-width
out_r  = in_r + arm_wall;             // outside half-width
tip_y  = r - out_r;                   // outer tip of the shell (negative)
pod_z0 = -wall - pod_depth;           // pod rim = top face of the lid
cav_r  = out_r - wall;                // pod cavity half-width
cav_tip_y = tip_y + wall;             // cavity tip (inner face)
cav_far_y = sleeve_len - wall;        // cavity far end (inner face)
pcb_y1 = pcb_y0 + pcb_l;
pcb_cy = (pcb_y0 + pcb_y1) / 2;
pcb_back_z = -wall - standoff_h;      // board back face
pcb_bot_z  = pcb_back_z - pcb_t;      // component side
sma_z  = pod_z0 + pod_depth / 2;
tooth  = snap_gap + snap_engage;
ufl    = gtu7_ufl_offset();

// --------------------------------------------------------- design checks ---
// Is a point inside the pod cavity's stadium outline, with margin m?
function in_cavity(p, m = 0) =
    p[1] >= r ? abs(p[0]) <= cav_r - m
              : norm([p[0], p[1] - r]) <= cav_r - m;

assert(in_cavity([ pcb_w / 2 + pcb_gap + latch_t, pcb_y0], 1),
       "Board/latch corner hits the rounded tip: increase pcb_y0");
assert(in_cavity([-pcb_w / 2 - pcb_gap - latch_t, pcb_y0], 1),
       "Board/latch corner hits the rounded tip: increase pcb_y0");
assert(pcb_y1 + 2.54 < sma_y - sma_keepout / 2,
       "SMA hardware overlaps the board/header: move sma_y");
assert(sma_y + sma_keepout / 2 <= cav_far_y,
       "SMA keep-out runs into the far wall: shorten sma_keepout or move sma_y");
assert(sma_z - sma_keepout / 2 > pod_z0 && sma_z + sma_keepout / 2 < -wall,
       "SMA keep-out does not fit the pod depth");
assert(pcb_bot_z - header_drop > pod_z0 + 1,
       "Header + plug is deeper than the pod: increase pod_depth");
assert(win_y1 + 6 < sleeve_len, "Port window too close to the open end");
assert(port_y > win_y0 + 3 && port_y < win_y1 - 3, "Port is not inside the window");

lid_strain   = snap_strain(tab_t, snap_engage, tab_len);
latch_strain = snap_strain(latch_t, pcb_gap + pcb_hook,
                           pcb_latch_len(standoff_h, pcb_t, pcb_play));
echo(str("Lid tab strain   = ", round(lid_strain * 1000) / 10, " %"));
echo(str("PCB latch strain = ", round(latch_strain * 1000) / 10, " %"));
assert(lid_strain < max_strain && latch_strain < max_strain,
       "Snap strain above max_strain: lengthen the arm, thin it, or reduce the hook");

// ------------------------------------------------------------ 2D plans ---
module dev_plan()  stadium(dev_width, dev_length);
module bore_plan() offset(r = fit_gap) dev_plan();

// Outside of sleeve and pod: handset outline grown by gap + arm, cut at the
// open end of the sleeve.
module outer_plan() {
    intersection() {
        offset(r = fit_gap + arm_wall) dev_plan();
        translate([-100, -100]) square([200, 100 + sleeve_len]);
    }
}
module cavity_plan() offset(delta = -wall) outer_plan();

// ------------------------------------------------------------- sleeve ---
module port_window() {
    translate([port_side * (in_r + out_r) / 2, (win_y0 + win_y1) / 2, port_z])
        x_slot(win_y1 - win_y0, win_h, arm_wall + 4, corner = 1.5);
}

module groove() {
    // Shallow channel on the outside of the arm, from the window down to z=0
    gz1 = port_z - win_h / 2 + 1;
    translate([port_side * out_r, port_y, gz1 / 2 - 1])
        cube([2 * groove_d, groove_w, gz1 + 2], center = true);
}

module sleeve() {
    difference() {
        union() {
            slab(-wall, wall) outer_plan();                                    // back plate
            slab(-eps, dev_depth + fit_gap + eps) difference() { outer_plan(); bore_plan(); }
            slab(dev_depth + fit_gap - eps, lip_t)                             // front lip
                difference() { outer_plan(); offset(delta = -front_lip) dev_plan(); }
        }
        port_window();
        if (cable_groove) groove();
    }
}

// ---------------------------------------------------------------- pod ---
module sma_hole_2d() {
    if (sma_flat > 0)
        intersection() {
            circle(d = sma_hole_d);
            translate([-sma_hole_d / 2, -sma_hole_d / 2]) square([sma_hole_d, sma_flat]);
        }
    else circle(d = sma_hole_d);
}

module sma_hole() {
    // The flat faces -Y, which is "up" when the body is printed standing.
    translate([sma_side * (out_r - wall / 2), sma_y, sma_z])
        rotate([0, 90, 0]) linear_extrude(height = wall + 2, center = true)
            mirror([0, 1]) sma_hole_2d();
}

module cable_notch() {
    // U-shaped notch open toward the lid; the lid closes it into a hole.
    translate([port_side * (out_r - wall / 2), port_y, 0]) hull() {
        translate([0, 0, pod_z0 - 1]) cube([wall + 2, notch_w, 2], center = true);
        translate([0, 0, pod_z0 + notch_h - notch_w / 2]) rotate([0, 90, 0])
            cylinder(d = notch_w, h = wall + 2, center = true, $fn = 32);
    }
}

// Where the three lid tabs live: [x, wall face y, rotation].
// Rotation 0 = tooth points +Y, 180 = tooth points -Y.
tab_places = [[0, cav_tip_y, 180], [-far_tab_x, cav_far_y, 0], [far_tab_x, cav_far_y, 0]];

module at_tabs(z) {
    for (p = tab_places)
        translate([p[0], p[1], z]) rotate([0, 0, p[2]]) translate([0, -snap_gap, 0])
            children();
}

module pod() {
    difference() {
        slab(pod_z0, pod_depth + eps) outer_plan();
        slab(pod_z0 - 1, pod_depth + 1) cavity_plan();
        sma_hole();
        cable_notch();
        at_tabs(pod_z0)
            tab_recess(w = tab_w, len = tab_len, tooth = tooth, gap = snap_gap);
    }
}

// --------------------------------------------------------- board mount ---
module board_mount() {
    for (s = [-1, 1])
        translate([0, pcb_cy, -wall]) mirror([s < 0 ? 1 : 0, 0, 0])
            translate([pcb_w / 2, 0, 0]) {
                pcb_side_latch(length = latch_len, t = latch_t, standoff = standoff_h,
                               pcb_t = pcb_t, gap = pcb_gap, hook = pcb_hook,
                               play = pcb_play);
                pcb_ledge(length = pcb_l - 6, width = 2, standoff = standoff_h);
            }
}

module body() { union() { sleeve(); pod(); board_mount(); } }

// ---------------------------------------------------------------- lid ---
module circuit_art() {
    // Decorative traces, clipped to stay 3 mm inside the lid edge.
    intersection() {
        offset(delta = -3) outer_plan();
        union() {
            for (x = [-12, -4, 4, 12]) {
                wire2d([[x, 2], [x, 14], [x * 0.5, 22], [x * 0.5, 48]]);
                translate([x, 2]) circle(d = 3.2, $fn = 32);
                translate([x * 0.5, 48]) circle(d = 3.2, $fn = 32);
            }
            wire2d([[-14, 30], [14, 30]]);
            translate([0, 30]) square(6, center = true);
        }
    }
}
module wire2d(pts) {
    for (i = [1 : len(pts) - 1])
        hull() { translate(pts[i - 1]) circle(d = trace_w, $fn = 16);
                 translate(pts[i])     circle(d = trace_w, $fn = 16); }
}

module lid_plate() {
    // Chamfered outside edge: hull of a slightly smaller bottom and full top.
    hull() {
        slab(0, eps) offset(delta = -lid_chamfer) outer_plan();
        slab(lid_chamfer, lid_t - lid_chamfer) outer_plan();
    }
}

// Lid in its own frame: outside face on z = 0, inside face on z = lid_t.
module lid() {
    difference() {
        lid_plate();
        translate([0, 0, -eps]) linear_extrude(height = trace_d + eps) circuit_art();
    }
    // Tabs: frame matches the pod when the lid's inside face meets the rim.
    at_tabs(lid_t - eps)
        cantilever_tab(w = tab_w, t = tab_t, len = tab_len, tooth = tooth);
}
module inlay() linear_extrude(height = trace_d) circuit_art();

// ------------------------------------------------------------ mockups ---
dev_side_x = port_side * r;
plug_len   = 4.3;
cable_x    = port_side * (out_r - (cable_groove ? groove_d : 0) + 0.5); // in groove
wall_x     = port_side * (out_r + 0.5);                                   // on the pod

cable_pts = [
    [dev_side_x + port_side * plug_len, port_y, port_z],   // plug tail
    [cable_x, port_y, port_z - 2],                         // out the window
    [cable_x, port_y, 0],                                  // down the groove
    [wall_x,  port_y, -3],                                 // onto the pod wall
    [wall_x,  port_y, pod_z0 + 2.5],                       // down the outside
    [port_side * (cav_r - 1.5), port_y, pod_z0 + 2.5],     // through the notch
    [-2, pcb_y1 - 1.3, pod_z0 + 2.5],                      // to the header
    [-2, pcb_y1 - 1.3, pcb_bot_z - header_drop]            // into the plug
];

ufl_world = [ufl[0], pcb_cy + ufl[1], pcb_back_z + ufl[2]];
coax_pts = [
    ufl_world,
    ufl_world + [0, 0, -3],
    [sma_side * (cav_r - 6.5), sma_y, sma_z]
];

module mockups() {
    tembed_mock(L = dev_length, W = dev_width, D = dev_depth,
                dial_d = dial_d, dial_h = dial_h,
                port_y = port_y, port_z = port_z, port_side = port_side);
    translate([dev_side_x, port_y, port_z]) mirror([port_side < 0 ? 1 : 0, 0, 0])
        qwiic_plug_mock(len = plug_len);
    translate([0, pcb_cy, pcb_back_z]) gtu7_mock(pcb = [pcb_w, pcb_l, pcb_t],
                                                 header_drop = header_drop);
    translate([sma_side * out_r, sma_y, sma_z]) mirror([sma_side < 0 ? 1 : 0, 0, 0])
        sma_bulkhead_mock(panel_t = wall);
    if (show_cable) {
        ribbon(cable_pts, n = 4, pitch = 1.0, d = 0.9);
        color("Gray") wire_path(coax_pts, d = 1.13);
    }
}

// Solid hardware used for the clash test (cables excluded: they are flexible
// and are supposed to touch the walls they route along).
// Parts that are SUPPOSED to touch (handset on the back plate, board on its
// ledges, SMA hardware against the inside of the wall) are nudged apart by contact_eps so the test reports real overlaps
// only, not zero-thickness contact faces.
contact_eps = 0.02;
module hardware_solids() {
    translate([0, 0, contact_eps]) tembed_mock(L = dev_length, W = dev_width, D = dev_depth,
                dial_d = dial_d, dial_h = dial_h,
                port_y = port_y, port_z = port_z, port_side = port_side);
    translate([dev_side_x, port_y, port_z]) mirror([port_side < 0 ? 1 : 0, 0, 0])
        qwiic_plug_mock(len = plug_len);
    translate([0, pcb_cy, pcb_back_z - contact_eps]) gtu7_mock(pcb = [pcb_w, pcb_l, pcb_t],
                                                 header_drop = header_drop);
    // SMA: only the hardware inside the wall can collide with the print
    translate([sma_side * (out_r - wall - contact_eps), sma_y, sma_z]) rotate([0, -sma_side * 90, 0])
        cylinder(d = sma_keepout, h = 6.5);
}

// -------------------------------------------------------- test coupons ---
// Print these first. They take minutes and tell you whether the real part fits.
module gauge() {
    // A short slice of the full body, laid flat (the slice is cut along Y).
    translate([0, 0, -(sleeve_len - gauge_y - gauge_len)]) stand()
        intersection() {
            body();
            translate([-100, gauge_y, -100]) cube([200, gauge_len, 200]);
        }
}

module sma_gauge() {
    n = len(sma_test_d);
    difference() {
        translate([-6, -7, 0]) cube([n * 10 + 2, 14, wall]);
        for (i = [0 : n - 1]) {
            d = sma_test_d[i];
            translate([i * 10, 0, -1]) linear_extrude(height = wall + 2)
                intersection() {                     // same D-flat rule as the pod
                    circle(d = d);
                    if (sma_flat > 0)
                        translate([-d / 2, -d / 2]) square([d, d - (sma_hole_d - sma_flat)]);
                    else circle(d = d);
                }
            // i + 1 notches on the edge identify the hole (1 = smallest)
            for (k = [0 : i]) translate([i * 10 - 2 + k * 1.2, 7 - 0.6, -1])
                cube([0.6, 1, wall + 2]);
        }
    }
}

// ------------------------------------------------------------- output ---
module stand() translate([0, 0, sleeve_len]) rotate([-90, 0, 0]) children();
module cut()   if (part == "section") keep_x_above(section_x) children(); else children();

lid_pose_z = pod_z0 - lid_t - lid_explode;

if (part == "body")  stand() body();
if (part == "lid")   lid();
if (part == "inlay") inlay();
if (part == "gauge") gauge();
if (part == "sma_gauge") sma_gauge();
if (part == "mockups") mockups();
if (part == "clash") {
    intersection() { body(); hardware_solids(); }
    intersection() { translate([0, 0, pod_z0 - lid_t]) lid(); hardware_solids(); }
}
if (part == "clash_view") {
    %body();
    %translate([0, 0, pod_z0 - lid_t]) lid();
    color("Red") {
        intersection() { body(); hardware_solids(); }
        intersection() { translate([0, 0, pod_z0 - lid_t]) lid(); hardware_solids(); }
    }
}
if (part == "preview" || part == "section") {
    cut() color("SteelBlue") body();
    cut() color("LightSteelBlue") translate([0, 0, lid_pose_z]) lid();
    cut() color("DarkOrange") translate([0, 0, lid_pose_z - eps]) inlay();
    if (show_mockups) cut() mockups();
}
