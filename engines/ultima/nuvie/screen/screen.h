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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef NUVIE_SCREEN_SCREEN_H
#define NUVIE_SCREEN_SCREEN_H

#include "ultima/shared/std/string.h"
#include "ultima/nuvie/core/game.h"
#include "ultima/nuvie/screen/surface.h"
#include "graphics/screen.h"

namespace Ultima {
namespace Nuvie {

class Configuration;

enum LightingStyle {
	LightingNone,
	LightingSmooth,
	LightingOriginal
};

class Screen {
private:
	const Configuration *config;
	Graphics::Screen *_rawSurface;
	RenderSurface *_renderSurface;

	bool is_no_darkness;
	bool non_square_pixels;

	uint16 width;
	uint16 height;

	Common::Rect shading_rect;
	uint8 *shading_data;
	uint8 *shading_globe[6];
	uint8 shading_ambient;
	uint8 *shading_tile[4];

public:
	Screen(const Configuration *cfg);
	~Screen();

	bool init();

	bool is_fullscreen() const;
	bool is_non_square_pixels() const {
		return non_square_pixels;
	}
	bool toggle_darkness_cheat();
	bool toggle_fullscreen();
	bool set_fullscreen(bool value);
	bool set_palette(const uint8 *palette);
	bool set_palette_entry(uint8 idx, uint8 r, uint8 g, uint8 b);
	bool rotate_palette(uint8 pos, uint8 length);
	bool clear(sint16 x, sint16 y, sint16 w, sint16 h, Common::Rect *clip_rect = nullptr);
	Graphics::ManagedSurface *create_sdl_surface_from(const byte *src_buf, uint16 src_bpp, uint16 src_w, uint16 src_h, uint16 src_pitch);
	Graphics::ManagedSurface *create_sdl_surface_8(const byte *src_buf, uint16 src_w, uint16 src_h);
	Graphics::ManagedSurface *get_sdl_surface();
	uint16 get_width() const {
		return width;
	}
	uint16 get_height() const {
		return height;
	}

	bool fill(uint8 colour_num, uint16 x, uint16 y, sint16 w, sint16 h);
	void fade(uint16 dest_x, uint16 dest_y, uint16 src_w, uint16 src_h, uint8 opacity, uint8 fade_bg_color = 0);
	void stipple_8bit(uint8 color_num);
	void stipple_8bit(uint8 color_num, uint16 x, uint16 y, uint16 w, uint16 h);
	void put_pixel(uint8 colour_num, uint16 x, uint16 y);

	bool blit(int32 dest_x, int32 dest_y, const byte *src_buf, uint16 src_bpp, uint16 src_w, uint16 src_h, uint16 src_pitch, bool trans = false, const Common::Rect *clip_rect = nullptr, uint8 opacity = 255);
	void blitbitmap(uint16 dest_x, uint16 dest_y, const byte *src_buf, uint16 src_w, uint16 src_h, uint8 fg_color, uint8 bg_color);

	void buildalphamap8();
	void clearalphamap8(uint16 x, uint16 y, uint16 w, uint16 h, uint8 opacity, bool party_light_source);
	void drawalphamap8globe(sint16 x, sint16 y, uint16 radius);
	void blitalphamap8(sint16 x, sint16 y, Common::Rect *clip_rect);

	LightingStyle get_lighting_style() const {
		return lighting_style;
	}
	LightingStyle get_old_lighting_style() const {
		return old_lighting_style;    // return the lighting_style before cheats applied
	}

	uint8 get_ambient() const {
		return shading_ambient;
	}
	void set_ambient(uint8 ambient) {
		shading_ambient = ambient;
	}

	void update();
	void update(int x, int y, uint16 w, uint16 h);
	void performUpdate();

	byte *copy_area(const Common::Rect *area = nullptr, byte *buf = nullptr);
	byte *copy_area(const Common::Rect *area, uint16 down_scale);

	void restore_area(byte *pixels, const Common::Rect *area = nullptr, byte *target = nullptr, const Common::Rect *target_area = nullptr, bool free_src = true);

	void draw_line(int sx, int sy, int ex, int ey, uint8 color);

	void get_mouse_location(int *x, int *y) const;

	void set_non_square_pixels(bool value);

protected:
	LightingStyle lighting_style, old_lighting_style;
	bool fill16(uint8 colour_num, uint16 x, uint16 y, sint16 w, sint16 h);

	bool fill32(uint8 colour_num, uint16 x, uint16 y, sint16 w, sint16 h);

	void fade16(uint16 dest_x, uint16 dest_y, uint16 src_w, uint16 src_h, uint8 opacity, uint8 fade_bg_color);
	void fade32(uint16 dest_x, uint16 dest_y, uint16 src_w, uint16 src_h, uint8 opacity, uint8 fade_bg_color);

	inline uint16 blendpixel16(uint16 p, uint16 p1, uint8 opacity);
	inline uint32 blendpixel32(uint32 p, uint32 p1, uint8 opacity);

	inline bool blit16(uint16 dest_x, uint16 dest_y, const byte *src_buf, uint16 src_bpp, uint16 src_w, uint16 src_h, uint16 src_pitch, bool trans);
	inline bool blit16WithOpacity(uint16 dest_x, uint16 dest_y, const byte *src_buf, uint16 src_bpp, uint16 src_w, uint16 src_h, uint16 src_pitch, bool trans, uint8 opacity);

	inline bool blit32(uint16 dest_x, uint16 dest_y, const byte *src_buf, uint16 src_bpp, uint16 src_w, uint16 src_h, uint16 src_pitch, bool trans);
	inline bool blit32WithOpacity(uint16 dest_x, uint16 dest_y, const byte *src_buf, uint16 src_bpp, uint16 src_w, uint16 src_h, uint16 src_pitch, bool trans, uint8 opacity);

	inline void blitbitmap16(uint16 dest_x, uint16 dest_y, const byte *src_buf, uint16 src_w, uint16 src_h, uint8 fg_color, uint8 bg_color);

	inline void blitbitmap32(uint16 dest_x, uint16 dest_y, const byte *src_buf, uint16 src_w, uint16 src_h, uint8 fg_color, uint8 bg_color);

	byte *copy_area16(const Common::Rect *area, uint16 down_scale);
	byte *copy_area32(const Common::Rect *area, uint16 down_scale);

	byte *copy_area16(const Common::Rect *area, byte *buf);
	byte *copy_area32(const Common::Rect *area, byte *buf);
	void restore_area16(byte *pixels, const Common::Rect *area, byte *target = nullptr, const Common::Rect *target_area = nullptr, bool free_src = true);
	void restore_area32(byte *pixels, const Common::Rect *area, byte *target = nullptr, const Common::Rect *target_area = nullptr, bool free_src = true);

	void set_screen_mode();
};

} // End of namespace Nuvie
} // End of namespace Ultima

#endif
