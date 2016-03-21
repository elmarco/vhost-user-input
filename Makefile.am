NULL =

bin_PROGRAMS = vhost-user-input

vhost_user_input_SOURCES =			\
	src/iov.c				\
	src/iov.h				\
	src/journal.c				\
	src/journal.h				\
	src/main.c				\
	src/vhost-user.c			\
	src/vhost-user.h			\
	src/virtio-input.h			\
	src/virtio-ring.h			\
	src/virtio.c				\
	src/virtio.h				\
	$(NULL)

vhost_user_input_CFLAGS = $(DEPS_CFLAGS)
vhost_user_input_LDADD = $(DEPS_LIBS)

MAINTAINERCLEANFILES = \
	$(GITIGNORE_MAINTAINERCLEANFILES_TOPLEVEL) \
	$(GITIGNORE_MAINTAINERCLEANFILES_MAKEFILE_IN) \
	$(GITIGNORE_MAINTAINERCLEANFILES_M4_LIBTOOL)

-include $(top_srcdir)/git.mk
