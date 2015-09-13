# contrib/data_encryption/Makefile

MODULE_big = data_encryption
OBJS = data_encryption.o

EXTENSION = data_encryption
DATA = data_encryption--1.1.sql

SHLIB_LINK = $(shell $(PG_CONFIG) --libdir)/pgcrypto.so

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/data_encryption
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
