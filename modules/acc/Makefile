# acc module makefile
#
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=acc.so
LIBS+=-lm

# set ENABLE_DIAMETER_ACC to true if you wish to enable DIAMETER accounting
#   (uncomment next line or 'ENABLE_DIAMETER_ACC=true make all')
#ENABLE_DIAMETER_ACC=true
ifeq ($(ENABLE_DIAMETER_ACC),true)
DEFS+=-DDIAM_ACC
endif

include ../../Makefile.modules
