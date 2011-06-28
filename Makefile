QUEUE_LIB=NFQUEUE
CC=gcc
CFLAGS=-Wall -O2 -std=gnu99 -march=i586 -mtune=i686 -fomit-frame-pointer \
		-ffast-math -D_GNU_SOURCE -D$(QUEUE_LIB)
INCLUDES	=	
LIBS	=	-lnetfilter_queue -lnfnetlink -lconfig -pthread
OBJS	=	$(shell ls *.c | sed 's/[.]c/.o/')
OBJS_D	=	$(shell ls *.c | sed 's/[.]c/.o/')
SRC_C	=	$(shell ls *.c)
TARGET 	=	udps

all: $(TARGET)

$(OBJS): $(SRC_C)
	$(CC) -c $(CFLAGS) $(INCLUDES) $(SRC_C)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(CFLAGS) $(OBJS) $(LIBS)
	strip $@

$(TARGET)-static: $(OBJS)
	$(CC) -static -o $@ $(CFLAGS) $(OBJS) $(LIBS)
	strip $@

clean:
	rm -f *.o *~ $(TARGET) $(TARGET)-static

install:
	install -m 755 $(TARGET) /opt/$(TARGET)

.PHONY: clean
