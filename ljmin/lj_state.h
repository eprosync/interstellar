/*
** State and stack handling.
** Copyright (C) 2005-2017 Mike Pall. See Copyright Notice in luajit.h
*/

#ifndef _LJ_STATE_H
#define _LJ_STATE_H

#include "lj_obj.h"

#define incr_top(L) \
  (++L->top >= tvref(L->maxstack) && (lj_state_growstack1(L), 0))

#define savestack(L, p)		((char *)(p) - mref(L->stack, char))
#define restorestack(L, n)	((TValue *)(mref(L->stack, char) + (n)))

#endif
