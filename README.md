# Crypter

I decided to create a tool to inject code into ELF64 formatted executables. Not because the world was really in need of another crypter, but because it was a great way to learn about the ELF format, executables in general, x64 assembly, and machine code. Probably learned few other things as well, but that's just what I can name off the top of my head. "Crypter" is also not the greatest name for a project, but it produces what it says on the label, and that's just what the file got named when I first created it :P

# So what the heck is this thing?

Ever wondered how hackers manage to jam viruses and stuff into executables? This is one of the ways you can go about doing that. In my case, I am not hiding a virus inside an executable, although this code could be adapted to do that. Instead I'm inserting what is known as a "crypter". What do those do? Well, if you were to look at a crypted executable on disk, the text (executable code) section of the executable would look like random garbage, but the real/original program will run fine because the executable will decrypt itself in memory during runtime. Techniques like this are typically used to evade antivirus, and to slow down forensic efforts.

# To build:

	make all

# To clean:

	make clean

# To run:

	./crypter <executable_name>

# Additional

The fib and hello_world executables are simply there for target practice.

Lastly, please don't try and use this for anything other then educational purposes. I'd be shocked if this software could actually produce undetectable executables. The encryption algorithm used is as simple as it can get (XOR), and will likely get picked up by modern security software.
