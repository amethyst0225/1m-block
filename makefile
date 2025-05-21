all: 1m-block

1m-block: 1m-block.o
	 gcc -o $@ $^ -lnetfilter_queue

1m-block.o: 1m-block.c
	 gcc -O2 -Wall -c $< -o $@

clean:
	 rm -f 1m-block *.o