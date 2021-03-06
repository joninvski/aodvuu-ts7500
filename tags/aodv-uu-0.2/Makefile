# Makefile

SRC =	main.c debug.c timer_queue.c aodv_socket.c aodv_hello.c \
	aodv_timeout.c routing_table.c seek_list.c k_route.c aodv_rreq.c \
	aodv_rrep.c aodv_rerr.c packet_input.c libipq.c icmp.c

OBJS =	$(SRC:%.c=%.o)

KERNEL=$(shell uname -r)

# Compiler and options:
CC=gcc
OPTS=-Wall -O3
# Uncomment to enable debug operation...
DEBUG=-g -DDEBUG
DEFS=$(DEBUG)
C_ALL= $(OPTS) $(DEFS)

# These are the options for the kernel modules:
KINC=-I/usr/src/linux/include
KDEFS=-D__KERNEL__ -DMODULE -DMODVERSIONS -include /usr/src/linux/include/linux/modversions.h
KC_ALL=-Wall -O2 $(KDEFS) $(KINC)

.PHONY: default clean install uninstall depend tags

all: aodvd kaodv.o ip_queue_aodv.o

.c.o:	$(SRC) Makefile
	$(CC) $(C_ALL) -c -o $@ $<

aodvd: $(OBJS) Makefile
	$(CC) $(C_ALL) -o $@ $(OBJS)

# Kernel modules:
kaodv.o: kaodv.c
	$(CC) $(KC_ALL) -c -o $@ $<

ip_queue_aodv.o: ip_queue_aodv.c
	$(CC) $(KC_ALL) -c -o $@ $<

tags:
	etags *.c *.h

depend:
	@echo "Updating Makefile dependencies..."
	@makedepend -Y./ -- $(DEFS) -- $(SRC) &>/dev/null
	@makedepend -a -Y./ -- $(KDEFS) kaodv.c &>/dev/null

install: all
	install -s -m 755 aodvd /usr/sbin/aodvd
	@if [ ! -d /lib/modules/$(KERNEL)/aodv ]; then \
		mkdir /lib/modules/$(KERNEL)/aodv; \
	fi
	install -m 644 kaodv.o /lib/modules/$(KERNEL)/aodv/kaodv.o
	install -m 644 ip_queue_aodv.o /lib/modules/$(KERNEL)/aodv/ip_queue_aodv.o
	/sbin/depmod -a
uninstall:
	rm -f /usr/sbin/aodvd
	rm -rf /lib/modules/$(KERNEL)/aodv

clean: 
	rm -f aodvd *~ *.o core *.log
# DO NOT DELETE

main.o: defs.h debug.h timer_queue.h params.h aodv_socket.h aodv_timeout.h
main.o: k_route.h routing_table.h aodv_hello.h aodv_rrep.h packet_input.h
debug.o: aodv_rreq.h defs.h aodv_rrep.h aodv_rerr.h routing_table.h debug.h
debug.o: params.h timer_queue.h
timer_queue.o: timer_queue.h defs.h debug.h
aodv_socket.o: aodv_socket.h defs.h timer_queue.h aodv_rreq.h aodv_rerr.h
aodv_socket.o: routing_table.h aodv_rrep.h aodv_hello.h debug.h
aodv_hello.o: aodv_hello.h defs.h aodv_rrep.h routing_table.h aodv_timeout.h
aodv_hello.o: aodv_rreq.h timer_queue.h params.h aodv_socket.h debug.h
aodv_timeout.o: defs.h aodv_timeout.h aodv_socket.h aodv_rreq.h aodv_rerr.h
aodv_timeout.o: routing_table.h timer_queue.h debug.h params.h packet_input.h
aodv_timeout.o: k_route.h seek_list.h
routing_table.o: routing_table.h defs.h aodv_timeout.h aodv_rerr.h
routing_table.o: aodv_socket.h k_route.h timer_queue.h debug.h params.h
seek_list.o: seek_list.h defs.h timer_queue.h aodv_timeout.h params.h
k_route.o: defs.h debug.h k_route.h
aodv_rreq.o: aodv_rreq.h defs.h aodv_rrep.h routing_table.h aodv_timeout.h
aodv_rreq.o: k_route.h timer_queue.h aodv_socket.h params.h seek_list.h
aodv_rreq.o: debug.h
aodv_rrep.o: aodv_rrep.h defs.h aodv_hello.h routing_table.h packet_input.h
aodv_rrep.o: aodv_timeout.h timer_queue.h aodv_socket.h seek_list.h debug.h
aodv_rrep.o: params.h
aodv_rerr.o: aodv_rerr.h defs.h routing_table.h aodv_socket.h debug.h
packet_input.o: defs.h debug.h routing_table.h aodv_rreq.h libipq.h params.h
packet_input.o: timer_queue.h aodv_timeout.h aodv_hello.h aodv_rrep.h
libipq.o: libipq.h
