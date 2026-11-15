// =============================================================================
// tutorial_steps.scad — walk through gps_cradle.scad one build step at a time
// Open this file, show the Customizer, and move the "step" slider.
// It includes the real design, so every step uses the same parameters.
// =============================================================================

include <gps_cradle.scad>
part = "none";      // silence gps_cradle.scad's own output (last assignment wins)

/* [Tutorial] */
step = 9; // [1:9]

ghost = true;       // show hardware as transparent stand-ins

// 1  2D plans: everything starts as a flat outline
if (step == 1) {
    color("Ivory")     slab(0.0, 0.2) dev_plan();
    color("Khaki")     slab(0.3, 0.2) difference() { bore_plan(); dev_plan(); }
    color("SteelBlue") slab(0.6, 0.2) difference() { outer_plan(); bore_plan(); }
    color("Tomato")    slab(0.9, 0.2) difference() { outer_plan(); cavity_plan(); }
}

// 2  Mock up the hardware before designing anything around it
if (step == 2) mockups();

// 3  Sleeve: back plate + side arms + front lip around the handset
if (step == 3) {
    color("SteelBlue") difference() {
        union() {
            slab(-wall, wall) outer_plan();
            slab(-eps, dev_depth + fit_gap + eps) difference() { outer_plan(); bore_plan(); }
            slab(dev_depth + fit_gap - eps, lip_t)
                difference() { outer_plan(); offset(delta = -front_lip) dev_plan(); }
        }
    }
    if (ghost) %tembed_mock(L = dev_length, W = dev_width, D = dev_depth,
                            dial_d = dial_d, dial_h = dial_h);
}

// 4  Port window: the cutting tool is shown in red with the # modifier
if (step == 4) {
    color("SteelBlue") sleeve();
    #port_window();
    if (cable_groove) #groove();
    translate([dev_side_x, port_y, port_z]) mirror([port_side < 0 ? 1 : 0, 0, 0])
        qwiic_plug_mock(len = plug_len);
}

// 5  GPS pod: a hollow slab under the back plate, open toward the lid
if (step == 5) {
    color("SteelBlue") sleeve();
    color("CadetBlue") difference() {
        slab(pod_z0, pod_depth + eps) outer_plan();
        slab(pod_z0 - 1, pod_depth + 1) cavity_plan();
    }
}

// 6  Holes in the pod: SMA bulkhead (D-flat), cable notch, snap recesses
if (step == 6) {
    color("SteelBlue") sleeve();
    color("CadetBlue") pod();
    #sma_hole();
    #cable_notch();
    #at_tabs(pod_z0) tab_recess(w = tab_w, len = tab_len, tooth = tooth, gap = snap_gap);
    translate([sma_side * out_r, sma_y, sma_z]) mirror([sma_side < 0 ? 1 : 0, 0, 0])
        sma_bulkhead_mock(panel_t = wall, show_keepout = true, keepout_d = sma_keepout);
}

// 7  Board mount: ledges + spring latches, with the GT-U7 proxy in place
if (step == 7) {
    color("SteelBlue") board_mount();
    color("SteelBlue", 0.25) slab(-wall, wall) outer_plan();
    translate([0, pcb_cy, pcb_back_z]) gtu7_mock(pcb = [pcb_w, pcb_l, pcb_t],
                                                 header_drop = header_drop);
}

// 8  Lid with snap tabs and the recessed circuit-art inlay
if (step == 8) {
    color("LightSteelBlue") lid();
    color("DarkOrange") translate([0, 0, -eps]) inlay();
}

// 9  Full assembly with cable routing
if (step == 9) {
    color("SteelBlue") body();
    color("LightSteelBlue") translate([0, 0, lid_pose_z]) lid();
    color("DarkOrange") translate([0, 0, lid_pose_z - eps]) inlay();
    mockups();
}
