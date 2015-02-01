CC=gcc
CFLAGS=-Wall -O2

MAIN_OBJS=ecrypt-sync.o mickey2_bitbybit.o main.o
BIGTEST_OBJS=ecrypt-sync.o mickey2_bitbybit.o bigtest_2.o

MAIN=main
BIGTEST=bigtest_2

all: $(MAIN) $(BIGTEST)

.c.o:
	$(CC) $(CFLAGS) -c $^ -o $@

$(MAIN): $(MAIN_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(BIGTEST): $(BIGTEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f *.o $(MAIN) $(BIGTEST)
