teardown: erase_registrations.c erase_registrations.h
	gcc -I../hack_library erase_registrations.c -lnet ../hack_library/hack_library.o -o erase_registrations
        
clean:
	rm -f erase_registrations erase_registrations.o

