СС = gcc
CFLAGS = -g -Wall -O3 -march=native -mtune=native
SRCMODULES = aes.c aes_tables.c
OBJMODULES = $(SRCMODULES:.c=.o)

%.o: %.c %.h
	$(СС) $(CFLAGS) -c $< -o $@

test: test.c $(OBJMODULES)
	$(СС) $(CFLAGS) $^ -o $@

bench: bench.c $(OBJMODULES)
	$(СС) $(CFLAGS) $^ -o $@

ifneq (clean, $(MAKECMDGOALS))
-include deps.mk
endif

deps.mk: $(SRCMODULES)
	$(CC) -MM $^ > $@

clean:
	rm -rf *.o test bench
