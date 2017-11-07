all: multi_block

netfilter_block: main.o
	g++ -o multi_block main.o -lnetfilter_queue

main.o : main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm *.o multi_block
