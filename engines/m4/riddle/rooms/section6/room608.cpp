/* ScummVM - Graphic Adventure Engine
 *
 * ScummVM is the legal property of its developers, whose names
 * are too numerous to list here. Please refer to the COPYRIGHT
 * file distributed with this source distribution.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/ },.
 *
 */

#include "m4/riddle/rooms/section6/room608.h"
#include "m4/riddle/rooms/section6/section6.h"
#include "m4/graphics/gr_series.h"
#include "m4/riddle/vars.h"
#include "m4/adv_r/adv_file.h"

namespace M4 {
namespace Riddle {
namespace Rooms {

static const int16 NORMAL_DIRS1[] = { 220, 221, -1 };
static const char *NORMAL_NAMES1[] = { "oldwk1", "oldwk3" };
static const int16 SHADOW_DIRS1[] = { 220, 231, -1 };
static const char *SHADOW_NAMES1[] = { "tt walker shadow 1", "oldwk3s" };


void Room608::init() {
	if (_G(flags)[V186] != 2) {
		_rp09 = series_load("608rp09");

		if (!inv_object_is_here("POLE") || _G(flags)[V186])
			kernel_load_variant("608lock1");
		else
			kernel_load_variant("608lock2");

		_old01 = series_load("608old01");
		_old02 = series_load("608old02");
		_old05 = series_load("608old05");
		_old08 = series_load("608old08");
		_old05a = series_load("608old05a");
		_old05b = series_load("608old05b");
		_old05c = series_load("608old05c");
		_old05d = series_load("608old05d");
		_old05f = series_load("608old05f");

		ws_walk_load_walker_series(NORMAL_DIRS1, NORMAL_NAMES1);
		ws_walk_load_shadow_series(SHADOW_DIRS1, SHADOW_NAMES1);
		_ol = TriggerMachineByHash(1, 1, 0, 0, 0, 0, 0, 0, 100, 0x200, 0,
			triggerMachineByHashCallbackNegative, "ol");
		sendWSMessage_10000(1, _ol, _old01, 1, 1, 200, _old01, 1, 1, 0);
		_val1 = 0;
		_val2 = 0;
		_val3 = 0;
	}

	if (inv_object_is_here("DRIFTWOOD STUMP")) {
		_stump = series_show("608ST_DN", 0xf00, 16);
		hotspot_set_active("DRIFTWOOD STUMP ", false);
	} else {
		hotspot_set_active("DRIFTWOOD STUMP", false);
	}

	if (inv_object_is_here("LIGHTER") && _G(flags)[V203] >= 7) {
		_lighter = series_show("608LITER", 0xf00, 16);
	} else {
		hotspot_set_active("LIGHTER", false);
	}

	if (!inv_object_is_here("DRIFTWOOD STUMP")) {
		hotspot_set_active("DRIFTWOOD STUMP ", false);
		hotspot_set_active("DRIFTWOOD STUMP  ", false);
	} else if (_G(flags)[V186]) {
		hotspot_set_active("DRIFTWOOD STUMP ", false);
	} else {
		_stump = series_show("608ST_UP", 0x400, 16);
		hotspot_set_active("DRIFTWOOD STUMP  ", false);
	}

	if (!inv_object_is_here("POLE")) {
		hotspot_set_active("POLE", false);
		hotspot_set_active("POLE ", false);
	} else if (_G(flags)[V186]) {
		hotspot_set_active("POLE", false);
	} else {
		_pole = series_show("608POLE", 0x400, 16);
		hotspot_set_active("POLE ", false);
	}

	if (inv_object_is_here("DRIFTWOOD PUFFIN")) {
		_puffin = series_show("608PUFIN", 0x400, 16);
	} else {
		hotspot_set_active("DRIFTWOOD PUFFIN", false);
	}

	switch (_G(flags)[V186]) {
	case 0:
		hotspot_set_active("hole in hillside", false);
		_end1 = series_show("608START", 0xf00, 16);
		hotspot_set_active("STATUE ", false);
		digi_preload("608_s01");
		digi_preload("608_s01a");
		break;
	case 1:
		hotspot_set_active("hole in hillside", false);
		_end1 = series_show("608END", 0xf00, 16);
		hotspot_set_active("STATUE", false);
		hotspot_set_active("stone", false);
		digi_preload("950_s37");
		break;
	case 2:
		hotspot_set_active("hole in hillside", true);
		_end1 = series_show("608END", 0xf00, 16);
		_end2 = series_show("608END2", 0xe00, 16);
		hotspot_set_active("STATUE", false);
		hotspot_set_active("stone", false);
		hotspot_set_active("old woman", false);
	default:
		break;
	}

	if (_G(flags)[V203] == 2) {
		_tt01 = series_load("608TT01");
		_rp01 = series_load("608RP01");

		player_set_commands_allowed(false);
		_G(player).disable_hyperwalk = true;
		ws_demand_location(-30, 345, 1);
		ws_walk(43, 345, nullptr, 18, 3);
	
		ws_walk_load_walker_series(SECTION6_NORMAL_DIRS, SECTION6_NORMAL_NAMES);
		ws_walk_load_shadow_series(SECTION6_SHADOW_DIRS, SECTION6_SHADOW_NAMES);

		_tt = triggerMachineByHash_3000(8, 9, SECTION6_NORMAL_DIRS, SECTION6_SHADOW_DIRS,
			-30, 324, 3, triggerMachineByHashCallback3000, "tt walker");
		sendWSMessage_10000(_tt, 105, 324, 5, 20, 1);
	} else if (_G(flags)[V203] == 6) {
		_tt02 = series_load("606TT02");
		_tt03 = series_load("608TT03");
		_tt05 = series_load("608TT05");
		_ripHandChin = series_load("RIP TREK HAND CHIN POS3");
		_ripTalker = series_load("RIP TREK TALKER POS3");
		_all5a = series_load("608all5a");
		_loop0 = series_load("608loop0");
		_loop1 = series_load("608loop1");

		player_set_commands_allowed(false);
		_G(player).disable_hyperwalk = true;
		ws_demand_location(-30, 345, 1);
		kernel_timing_trigger(1, 698);

		ws_walk_load_walker_series(SECTION6_NORMAL_DIRS, SECTION6_NORMAL_NAMES);
		ws_walk_load_shadow_series(SECTION6_SHADOW_DIRS, SECTION6_SHADOW_NAMES);

		_tt = triggerMachineByHash_3000(8, 9, SECTION6_NORMAL_DIRS, SECTION6_SHADOW_DIRS,
			-30, 324, 3, triggerMachineByHashCallback3000, "tt walker");
		sendWSMessage_10000(_tt, 103, 318, 3, 700, 1);
	}

	switch (_G(game).previous_room) {
	case KERNEL_RESTORING_GAME:
		digi_preload("950_s28b");
		break;

	case 603:
		digi_preload("950_s28b");
		digi_stop(3);
		digi_unload("950_s28a");
		break;

	case 605:
		digi_preload("950_s28b");
		digi_stop(3);
		digi_unload("950_s28");

		if (_G(flags)[V203] != 2) {
			player_set_commands_allowed(false);
			ws_demand_location(-30, 345, 3);
			ws_walk(43, 345, nullptr, 1, 3);
		}
		break;

	default:
		digi_preload("950_s28b");
		break;
	}

	series_play("608surf", 0xf00, 0, -1, 15, -1, 100, 0, 0, 0, -1);
	digi_play_loop("950_s28b", 3, 90);
}

void Room608::daemon() {
}

void Room608::pre_parser() {
	bool takeFlag = player_said("take");
	bool useFlag = player_said_any("push", "pull", "gear", "open", "close");

	if (player_said("HORN/PULL CORD", "WATER") && !_G(flags)[GLB_TEMP_3])
		_G(player).resetWalk();
	if (player_said("POLE", "DRIFTWOOD STUMP ") && inv_player_has("POLE"))
		_G(player).resetWalk();
	if (useFlag && HERE("POLE"))
		_G(player).resetWalk();
	if (player_said("DRIFTWOOD STUMP", "LARGE HOLE") && inv_player_has("DRIFTWOOD STUMP"))
		_G(player).resetWalk();
	if (takeFlag && HAS("POLE"))
		_G(player).resetWalk();
}

void Room608::parser() {
	bool lookFlag = player_said_any("look", "look at");
	bool talkFlag = player_said_any("talk", "talk to");
	bool takeFlag = player_said("take");
	bool useFlag = player_said_any("push", "pull", "gear", "open", "close");

	if (player_said("conv608a")) {
		conv608a();
	} else if (_G(kernel).trigger == 747) {
		_val3 = 1;
		_val4 = 2;
	} else if (talkFlag && player_said("old woman")) {
		if (_G(flags)[GLB_TEMP_7]) {
			digi_play(_G(flags)[V203] > 2 ? "608r04" : "608r35", 1);
		} else {
			if (_G(flags)[V203] >= 2 || !_G(flags)[V034]) {
				player_set_commands_allowed(false);
				_G(flags)[V034] = 1;

				player_update_info();
				_shadow = series_show("safari shadow 3", 0xf00, 0, -1, -1, 0,
					_G(player_info).scale, _G(player_info).x, _G(player_info).y);
				ws_hide_walker();
				_ripley = TriggerMachineByHash(1, 1, 0, 0, 0, 0, 0, 0, 100, 0x100, 0,
					triggerMachineByHashCallbackNegative, "rip");

				_G(kernel).trigger_mode = KT_DAEMON;
				sendWSMessage_10000(1, _ripley, _rp09, 1, 23, 300, _rp09, 23, 23, 0);
				_G(kernel).trigger_mode = KT_PARSE;

				_val5 = 0;
				_val4 = 0;
				_val3 = 6;
				conv_load("conv608a", 10, 10, 747);
				conv_export_value_curr(_G(flags)[V203] >= 3 ? 1 : 0, 0);
				conv_play();
			} else {
				digi_play("608r35", 1);
			}
		}
	} else if (takeFlag && player_said("DRIFTWOOD STUMP") && takeStump1()) {
		// No implementation
	} else if (takeFlag && player_said("DRIFTWOOD PUFFIN") && takePuffin()) {
		// No implementation
	} else if (player_said("DRIFTWOOD STUMP", "LARGE HOLE") && stumpHole()) {
		// No implementation
	} else if (takeFlag && player_said("DRIFTWOOD STUMP ") && takeStump2()) {
		// No implementation
	} else if (takeFlag && player_said("LIGHTER") && takeLighter()) {
		// No implementation
	} else if (player_said("HORN/PULL CORD/WATER", "WATER")) {
		digi_play("608r72", 1);
	} else if (player_said("DRIFTWOOD STUMP") && player_said_any("STATUE", "STATUE ")) {
		digi_play("com019", 1);
	} else if (player_said("HORN/PULL CORD", "WATER") && hornCordWater()) {
		// No implementation
	} else if (player_said("POLE", "DRIFTWOOD STUMP ") && inv_player_has("POLE")) {
		switch (_G(kernel).trigger) {
		case -1:
			ws_walk(453, 311, nullptr, 1, 1);
			break;
		case 1:
			player_set_commands_allowed(false);
			player_update_info();
			ws_hide_walker();
			kernel_load_variant("608lock2");
			digi_preload("608_s03");

			_shadow5 = series_show("safari shadow 1", _G(player_info).depth,
				16, -1, -1, 0, _G(player_info).scale,
				_G(player_info).x, _G(player_info).y);
			_horn = series_load("608rp03");
			_ol2 = TriggerMachineByHash(1, 1, 0, 0, 0, 0, 0, 0, 100, 0x100, 0,
				triggerMachineByHashCallbackNegative, "ol");
			sendWSMessage_10000(1, _ol2, _horn, 1, 24, 2, _horn, 24, 24, 0);
			break;
		case 2:
			sendWSMessage_10000(1, _ol2, _horn, 25, 39, 3, _horn, 39, 39, 0);
			digi_play("608_s03", 2);
			break;
		case 3:
			digi_stop(2);
			digi_unload("608_s03");
			terminateMachineAndNull(_ol2);
			series_unload(_horn);
			terminateMachineAndNull(_shadow5);

			_pole = series_show("608POLE", 0x400, 16);
			hotspot_set_active("POLE", true);
			ws_unhide_walker();
			inv_move_object("POLE", 608);
			player_set_commands_allowed(true);
			break;
		default:
			break;
		}
	} else if (takeFlag && player_said("POLE") && !inv_player_has("POLE")) {
		switch (_G(kernel).trigger) {
		case -1:
			ws_walk(453, 311, nullptr, 1, 1);
			break;
		case 1:
			player_set_commands_allowed(false);
			player_update_info();
			ws_hide_walker();
			kernel_load_variant("608lock1");
			terminateMachineAndNull(_pole);

			_shadow5 = series_show("safari shadow 1", _G(player_info).depth,
				16, -1, -1, 0, _G(player_info).scale,
				_G(player_info).x, _G(player_info).y);
			_horn = series_load("608rp03");
			_ol2 = TriggerMachineByHash(1, 1, 0, 0, 0, 0, 0, 0, 100, 0x100, 0,
				triggerMachineByHashCallbackNegative, "ol");
			sendWSMessage_10000(1, _ol2, _horn, 39, 1, 2, _horn, 1, 1, 0);
			break;
		case 2:
			terminateMachineAndNull(_ol2);
			series_unload(_horn);
			terminateMachineAndNull(_shadow5);
			hotspot_set_active("POLE", false);
			ws_unhide_walker();
			inv_give_to_player("POLE");
			player_set_commands_allowed(true);
			break;
		default:
			break;
		}
	} else if (useFlag && HERE("POLE")) {
		switch (_G(kernel).trigger) {
		case -1:
			ws_walk(453, 311, nullptr, 1, 1);
			break;
		case 1:
			player_set_commands_allowed(false);
			player_update_info();
			ws_hide_walker();
			kernel_load_variant("608lock1");
			digi_preload("950_s37");
			digi_preload("950_s37a");

			_ol2 = series_stream("608rp04", 5, 0x300, 16);
			series_stream_break_on_frame(_ol2, 25, 3);
			break;
		case 3:
			series_stream_break_on_frame(_ol2, 33, 30);
			digi_play("950_s37", 2);
			break;
		case 4:
			series_stream_break_on_frame(_ol2, 76, 5);
			digi_play("950_s37a", 2);
			break;
		case 5:
			series_stream_break_on_frame(_ol2, 77, 7);
			digi_play("950_s37", 2);
			break;
		case 7:
			terminateMachineAndNull(_end1);
			terminateMachineAndNull(_pole);
			terminateMachineAndNull(_stump);
			_val3 = 8;
			digi_play("608_s01a", 1);
			break;
		case 10:
			digi_unload("950_s37");
			digi_unload("950_s37a");
			_G(flags)[V186] = 1;
			_end1 = series_show("608END", 0xf00, 16);

			hotspot_set_active("STATUE", false);
			hotspot_set_active("STATUE ", true);
			hotspot_set_active("DRIFTWOOD STUMP ", false);
			hotspot_set_active("DRIFTWOOD STUMP  ", true);
			hotspot_set_active("POLE", false);
			hotspot_set_active("POLE ", true);
			hotspot_set_active("stone", false);

			ws_unhide_walker();
			player_update_info();
			ws_walk(_G(player_info).x + 1, _G(player_info).y,
				nullptr, 12, 4);
			break;
		case 12:
			_ripLHandTalk = series_load("RIP TREK L HAND TALK POS4");
			setGlobals1(_ripLHandTalk, 2, 6, 6, 7, 1, 6, 1, 1, 1);
			digi_play("608r15", 1, 255, 15);
			break;
		case 15:
			sendWSMessage_120000(2);
			_val3 = 10;
			digi_play("608o01", 1, 255, 18);
			break;
		case 18:
			sendWSMessage_110000(2);
			digi_play("608r16", 1, 255, 20);
			break;
		case 20:
			sendWSMessage_140000(-1);
			_val3 = 9;
			digi_play("608o02", 1, 255, 22);
			break;
		case 22:
			_val3 = 1;
			kernel_timing_trigger(1, 200, KT_DAEMON, KT_PARSE);
			kernel_timing_trigger(100, 25);
			break;
		case 25:
			player_set_commands_allowed(true);
			digi_play("608r17", 1);
			break;
		case 30:
			series_stream_break_on_frame(_ol2, 44, 4);
			digi_play("608_s01", 1);
			break;
		default:
			break;
		}
	} else if (player_said_any("lung", "prostate")) {
		switch (_G(kernel).trigger) {
		case 1:
			player_set_commands_allowed(false);
			player_update_info();
			_shadow = series_show("safari shadow 3", 0xf00, 0, -1, -1, 0,
				_G(player_info).scale, _G(player_info).x, _G(player_info).y);

			ws_hide_walker();
			_ripley = TriggerMachineByHash(1, 1, 0, 0, 0, 0, 0, 0, 100, 0x100, 0,
				triggerMachineByHashCallbackNegative, "rip");

			_G(kernel).trigger_mode = KT_DAEMON;
			sendWSMessage_10000(1, _ripley, _rp09, 1, 23, 300, _rp09, 23, 23, 0);
			_G(kernel).trigger_mode = KT_PARSE;

			_val5 = 0;
			_val4 = 1;
			_val3 = 6;
			digi_play("608r70", 1, 255, 2);
			break;
		case 2:
			_val3 = 5;
			_val4 = 0;
			digi_play("608o18", 1, 255, 3);
			break;
		case 3:
			_val3 = 6;
			kernel_timing_trigger(1, 200, KT_DAEMON, KT_PARSE);
			_val4 = 1;
			digi_play("608r71", 1, 255, 5);
			break;
		case 5:
			_val4 = player_said("lung") ? 3 : 4;
			break;
		default:
			break;
		}
	} else if (player_said("obsidian disk", "old woman") &&
			!inv_object_is_here("CLOCK FACING")) {
		if (_G(flags)[V186]) {
			Common::strcpy_s(_G(player).verb, "lung");
			kernel_timing_trigger(1, 1);
		} else {
			digi_play(_G(flags)[GLB_TEMP_4] ? "608r04a" : "608r35a", 1);
		}
	} else if (player_said("clock facing", "old woman") &&
			!inv_object_is_here("OBSIDIAN DISK")) {
		if (_G(flags)[V186]) {
			Common::strcpy_s(_G(player).verb, "prostate");
			kernel_timing_trigger(1, 1);
		} else {
			digi_play(_G(flags)[GLB_TEMP_4] ? "608r04a" : "608r35a", 1);
		}
	} else if (player_said_any("bowels", "scrotum")) {
		switch (_G(kernel).trigger) {
		case 1:
			player_set_commands_allowed(false);
			player_update_info();
			_shadow = series_show("safari shadow 3", 0xf00, 0, -1, -1, 0,
				_G(player_info).scale, _G(player_info).x, _G(player_info).y);

			ws_hide_walker();
			_ripley = TriggerMachineByHash(1, 1, 0, 0, 0, 0, 0, 0, 100, 0x100, 0,
				triggerMachineByHashCallbackNegative, "rip");

			_G(kernel).trigger_mode = KT_DAEMON;
			sendWSMessage_10000(1, _ripley, _rp09, 1, 23, 300, _rp09, 23, 23, 0);
			_G(kernel).trigger_mode = KT_PARSE;

			_val5 = 0;
			_val4 = 1;
			_val3 = 6;
			digi_play("608r67", 1, 255, 2);
			break;
		case 2:
			_val3 = 5;
			_val4 = 0;
			digi_play("608o17", 1, 255, 3);
			break;
		case 3:
			_val3 = 6;
			kernel_timing_trigger(1, 200, KT_DAEMON, KT_PARSE);
			_val4 = 1;
			digi_play("608r68", 1, 255, 5);
			break;
		case 5:
			_val4 = player_said("bowels") ? 5 : 6;
			break;
		default:
			break;
		}
	} else if (player_said("obsidian disk", "old woman") &&
			inv_object_is_here("CLOCK FACING")) {
		Common::strcpy_s(_G(player).verb, "bowels");
		kernel_timing_trigger(1, 1);
	} else if (player_said("clock facing", "old woman") &&
			inv_object_is_here("OBSIDIAN DISK")) {
		Common::strcpy_s(_G(player).verb, "bowels");
		kernel_timing_trigger(1, 1);
	} else if (lookFlag && player_said("statue")) {
		digi_play(_G(flags)[V203] > 1 ? "608r05" : "608r36", 1);
	} else if (lookFlag && player_said("statue ")) {
		digi_play(_G(flags)[V203] == 1 ? "608r38" : "608r52", 1);
	} else if (lookFlag && player_said("stone")) {
		digi_play(_G(flags)[V186] ? "608r39" : "608r06", 1);
	} else if (lookFlag && player_said("base")) {
		digi_play("608r07", 1);
	} else if (lookFlag && player_said("small hole")) {
		digi_play("608r09", 1);
	} else if (lookFlag && player_said("lava")) {
		digi_play("608r08", 1);
	} else if (lookFlag && player_said("crevice")) {
		digi_play("608r09", 1);
	} else if (lookFlag && player_said("large hole")) {
		digi_play(inv_object_is_here("DRIFTWOOD STUMP") ?
			"608r40" : "608r10", 1);
	} else if (lookFlag && player_said(" ")) {
		digi_play("608r11", 1);
	} else if (lookFlag && HERE("DRIFTWOOD PUFFIN") && lookPuffin()) {
		// No implementation
	} else if (player_said("left")) {
		switch (_G(kernel).trigger) {
		case -1:
			player_set_commands_allowed(false);
			disable_player_commands_and_fade_init(1);
			break;
		case 1:
			digi_stop(1);
			adv_kill_digi_between_rooms(false);
			digi_play_loop("950_s28b", 3, 90);
			_G(game).setRoom(605);
			break;
		default:
			break;
		}
	} else if (lookFlag && player_said("DRIFTWOOD STUMP") &&
			inv_object_in_scene("DRIFTWOOD STUMP", 600)) {
		digi_play("608r13", 1);
	} else if (lookFlag && player_said("DRIFTWOOD STUMP ")) {
		digi_play("608r76", 1);
	} else if (lookFlag && player_said("DRIFTWOOD STUMP  ")) {
		digi_play("608r41", 1);
	} else if (lookFlag && player_said("water")) {
		digi_play("608r73", 1);
	} else if (player_said("POLE", "STATUE") ||
			player_said("POLE", "STATUE ")) {
		digi_play("608r77", 1);
	} else if (lookFlag && player_said("old woman")) {
		if (_G(flags)[V203] > 2) {
			if (++_G(flags)[V181] > 3)
				_G(flags)[V181] = 3;

			switch (_G(flags)[V181]) {
			case 1:
				digi_play("608r14", 1);
				break;
			case 2:
				digi_play("608r14a", 1);
				break;
			case 3:
				digi_play("608r14b", 1);
				break;
			default:
				break;
			}
		} else {
			digi_play("608r37", 1);
		}
	} else if (lookFlag && HERE("LIGHTER")) {
		digi_play("608r66", 1);
	} else if (lookFlag && player_said("hole in hillside")) {
		digi_play("608r51a", 1);
	} else if (player_said("WHALE BONE HORN", "WATER")) {
		digi_play("608r64", 1);
	} else if (player_said("OBSIDIAN DISK", "STATUE") ||
			player_said("OBSIDIAN DISK", "STATUE ") ||
			player_said("CLOCK FACING", "STATUE") ||
			player_said("CLOCK FACING", "STATUE ")) {
		digi_play("com146", 1, 255, -1, 997);
	} else if (takeFlag && player_said("pole ")) {
		digi_play("608r18", 1);
	} else if (takeFlag && player_said("stone")) {
		digi_play("608r63", 1);
	} else if (lookFlag && HERE("pole")) {
		digi_play("608r75", 1);
	} else if (lookFlag && HERE("pole ")) {
		digi_play("608r42", 1);
	} else if (takeFlag && player_said("driftwood stump  ")) {
		digi_play("608r19", 1);
	} else {
		return;
	}

	_G(player).command_ready = false;
}

void Room608::conv608a() {
	const char *sound = conv_sound_to_play();
	int who = conv_whos_talking();
	int node = conv_current_node();
	int entry = conv_current_entry();

	if (_G(kernel).trigger == 1) {
		if (who <= 0) {
			_val3 = 6;
			kernel_timing_trigger(1, 200, KT_DAEMON, KT_PARSE);
		} else if (who == 1) {
			_val4 = 0;
		}

		conv_resume();

	} else if (sound) {
		if (who <= 0) {
			if (node == 4 && entry == 0)
				midi_play("eastiswo", 255, 0, -1, 949);
			if ((node == 2 && entry == 1) || (node == 3 && entry == 2))
				_val3 = 7;
			else if ((node == 2 && entry == 0) || (node == 3 && entry == 1))
				_val3 = 12;
			else
				_val3 = 5;
		} else if (who == 1) {
			if (node == 4)
				_G(flags)[GLB_TEMP_7] = 1;
			if (!(node == 5 && entry == 3))
				_val4 = 1;
		}

		digi_play(sound, 1, 255, 1);
	} else {
		conv_resume();
	}
}

bool Room608::takeStump1() {
	switch (_G(kernel).trigger) {
	case -1:
		if (inv_object_in_scene("DRIFTWOOD STUMP", 600)) {
			player_set_commands_allowed(false);
			_ripLowReach = series_load("RIP LOW REACH POS1");
			setGlobals1(_ripLowReach, 1, 10, 10, 10);
			sendWSMessage_110000(2);
			return true;
		}
		break;

	case 2:
		hotspot_set_active("DRIFTWOOD STUMP", false);
		inv_give_to_player("DRIFTWOOD STUMP");
		kernel_examine_inventory_object("PING DRIFTWOOD STUMP",
			5, 1, 230, 244, 3);
		return true;

	case 3:
		sendWSMessage_140000(5);
		return true;

	default:
		break;
	}

	return false;
}

bool Room608::takePuffin() {
	switch (_G(kernel).trigger) {
	case -1:
		if (inv_object_is_here("DRIFTWOOD PUFFIN")) {
			player_set_commands_allowed(false);
			_ripLowReach2 = series_load("RIP LOW REACH POS2");
			setGlobals1(_ripLowReach2, 1, 16, 16, 16);
			sendWSMessage_110000(2);
			return true;
		}
		break;

	case 2:
		hotspot_set_active("DRIFTWOOD PUFFIN", false);
		inv_give_to_player("DRIFTWOOD PUFFIN");
		kernel_examine_inventory_object("PING DRIFTWOOD PUFFIN",
			5, 1, 142, 239, 3);
		terminateMachineAndNull(_puffin);
		return true;

	case 3:
		sendWSMessage_140000(5);
		return true;

	case 5:
		series_unload(_ripLowReach2);
		break;

	default:
		break;
	}

	return false;
}

bool Room608::stumpHole() {
	switch (_G(kernel).trigger) {
	case -1:
		if (inv_player_has("DRIFTWOOD STUMP")) {
			ws_walk(474, 309, nullptr, 1, 2);
			return true;
		}
		break;

	case 1:
		player_set_commands_allowed(false);
		_ripLowReach = series_load("RIP LOW REACH POS1");
		setGlobals1(_ripLowReach, 1, 10, 10, 10);
		sendWSMessage_110000(2);
		return true;

	case 2:
		hotspot_set_active("DRIFTWOOD STUMP ", true);
		inv_move_object("DRIFTWOOD STUMP", 608);
		_stump = series_show("608ST_UP", 0x400, 16);
		sendWSMessage_140000(5);
		digi_play("608_s02", 2);
		return true;

	case 5:
		series_unload(_ripLowReach);
		player_set_commands_allowed(true);
		return true;

	default:
		break;
	}

	return false;
}

bool Room608::takeStump2() {
	if (inv_object_is_here("POLE")) {
		digi_play("608r74", 1);
		return true;
	} else {
		switch (_G(kernel).trigger) {
		case -1:
			ws_walk(474, 309, nullptr, 1, 2);
			return true;

		case 1:
			player_set_commands_allowed(false);
			_ripLowReach = series_load("RIP LOW REACH POS1");
			setGlobals1(_ripLowReach, 1, 10, 10, 10);
			sendWSMessage_110000(2);
			return true;

		case 2:
			hotspot_set_active("DRIFTWOOD STUMP ", false);
			terminateMachineAndNull(_stump);
			inv_give_to_player("DRIFTWOOD STUMP");
			sendWSMessage_140000(5);
			return true;

		case 5:
			series_unload(_ripLowReach);
			player_set_commands_allowed(true);
			return true;

		default:
			break;
		}

		return false;
	}
}

bool Room608::takeLighter() {
	switch (_G(kernel).trigger) {
	case -1:
		if (inv_object_is_here("LIGHTER")) {
			player_set_commands_allowed(false);
			_ripLowReach = series_load("RIP LOW REACH POS1");
			return true;
		}
		break;

	case 2:
		hotspot_set_active("LIGHTER", false);
		inv_give_to_player("LIGHTER");
		kernel_examine_inventory_object("PING LIGHTER", 5, 1, 455, 250, 3);
		terminateMachineAndNull(_lighter);
		return true;

	case 3:
		sendWSMessage_140000(5);
		return true;

	case 5:
		series_unload(_ripLowReach);
		player_set_commands_allowed(true);
		return true;

	default:
		break;
	}

	return false;
}

bool Room608::hornCordWater() {
	if (_G(flags)[V193]) {
		digi_play("com118", 1);
		return true;
	} else {
		switch (_G(kernel).trigger) {
		case -1:
			ws_walk(64, 354, nullptr, 1, 7);
			return true;

		case 1:
			player_set_commands_allowed(false);
			player_update_info();
			ws_hide_walker();
			digi_preload("608_s08");

			_shadow5 = series_show("safari shadow 5", _G(player_info).depth, 144, -1, -1, 0,
				_G(player_info).scale, _G(player_info).x, _G(player_info.y));
			_ol2 = TriggerMachineByHash(1, 1, 0, 0, 0, 0, 0, 0, 100, 0x100, 0,
				triggerMachineByHashCallbackNegative, "ol");
			sendWSMessage_10000(1, _ol2, _horn, 1, 16, 2, _horn, 16, 16, 0);
			return true;

		case 2:
			sendWSMessage_10000(1, _ol2, _horn, 17, 37, 3, _horn, 37, 37, 0);
			digi_play("608_s08", 2);
			return true;

		case 3:
			inv_give_to_player("HORN/PULL CORD/WATER");
			inv_move_object("HORN/PULL CORD", NOWHERE);
			kernel_examine_inventory_object("PING HORN/PULL CORD/WATER",
				5, 1, 42, 239, 4);
			return true;

		case 4:
			digi_unload("608_s08");
			terminateMachineAndNull(_ol2);
			series_unload(_horn);
			terminateMachineAndNull(_shadow5);
			ws_unhide_walker();
			_G(flags)[GLB_TEMP_3] = 1;
			player_set_commands_allowed(true);
			digi_play("608r65", 1);
			return true;

		default:
			break;
		}

		return false;
	}
}

bool Room608::lookPuffin() {
	switch (_G(kernel).trigger) {
	case -1:
		if (_G(flags)[V187]) {
			digi_play("608r12", 1);
		} else {
			player_set_commands_allowed(false);
			digi_play("608r12", 1, 255, 1);
		}
		return true;

	case 1:
		_G(flags)[V187] = 1;
		player_set_commands_allowed(true);
		digi_play("608r12a", 1);
		return true;

	default:
		break;
	}

	return false;
}

} // namespace Rooms
} // namespace Riddle
} // namespace M4
