/*
  File: walk_tree.h

  Copyright (C) 2007 Andreas Gruenbacher <a.gruenbacher@computer.org>

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Library General Public License for more details.

  You should have received a copy of the GNU Library General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef __WALK_TREE_H
#define __WALK_TREE_H

#define WALK_TREE_RECURSIVE	0x1
#define WALK_TREE_PHYSICAL	0x2
#define WALK_TREE_LOGICAL	0x4
#define WALK_TREE_DEREFERENCE	0x8

#define WALK_TREE_SYMLINK	0x10
#define WALK_TREE_FAILED	0x20

struct stat;

extern int walk_tree(const char *path, int walk_flags,
		     int (*func)(const char *, const struct stat *, int, void *),
		     void *arg);

#endif
