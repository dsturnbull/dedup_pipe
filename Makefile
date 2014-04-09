CFLAGS=-I. -std=c11 -g
LDFLAGS=-lcrypto
SRCS=$(wildcard src/*.c)
OBJS=$(SRCS:%.c=%.o)

all: src/dedup_pipe

src/dedup_pipe: $(OBJS)

clean:
	rm -f $(OBJS)

.depend: depend
depend: $(SRCS)
	@rm -f .depend
	@$(CC) $(CFLAGS) -MM $^ >> .depend 2>/dev/null ; true
	@sed -e 's/\(^[^.]*\.o\)/src\/\1/' -i._ .depend
	@rm -f .depend._

-include .depend

.PHONY: clean
