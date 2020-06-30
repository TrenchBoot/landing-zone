/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __EVENT_LOG_H__
#define __EVENT_LOG_H__

int event_log_init(struct tpm *tpm);

int log_event_tpm12(u32 pcr, u8 sha1[20], char *event);
int log_event_tpm20(u32 pcr, u8 sha1[20], u8 sha256[32], char *event);

#endif /* __EVENT_LOG_H__ */
