#include <stdio.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#define XOR_BYTE 0x77
#define STUB_SIZE 115
#define FALSE 0
#define TRUE 1

//Just print out some general information found in the Elf64_Ehdr
void elfStat(Elf64_Ehdr elfHeader)
{
	printf("[*] ELF entry point is at 0x%lx.\n", elfHeader.e_entry);
	printf("[*] Start of section headers: %lu.\n", elfHeader.e_shoff);
	printf("[*] Size of a section header entry: %d.\n", elfHeader.e_shentsize);
	printf("[*] Number of entries in the section header table: %d.\n", elfHeader.e_shnum);
	printf("[*] Index of the section header table entry containing section names: %d.\n", elfHeader.e_shstrndx);
}

//Check to make sure this is really an ELF file.
int isValidImage(FILE* image)
{
	Elf64_Ehdr elfHeader;
	char elf_magic[4] = {0x7F, 0x45, 0x4C, 0x46};

	rewind(image);
	fread(&elfHeader, sizeof(elfHeader), 1, image);

	if(memcmp(elfHeader.e_ident, elf_magic, sizeof(elf_magic)) != 0)
	{
		printf("[X] Elf magic not detected. Are you sure this file is an ELF executable? Terminating.\n");
		return FALSE;
	}
	else
	{
		printf("[*] Input image validation successful.\n");
		elfStat(elfHeader);
	}

	return TRUE;
}

//Finds the largest code cave currently in the target image
//Returns offset of best code cave on success, returns -1 on failure.
//Remember that if you call this AFTER writing the stub to the target, you will not be returned the same address as before.
int findCave(FILE* image)
{
	fseek(image, 0L, SEEK_END);
	unsigned long fileSize = ftell(image);
	rewind(image);

	char imageBuf[fileSize];
	fread(&imageBuf, fileSize, 1, image);

	unsigned long count = 0;
	unsigned long bestLocation = 0;
	unsigned long biggestCave = 0;

	for(unsigned long i = 0; i < fileSize; i++) //For each byte in the file
	{
		if(imageBuf[i] == 0x00) //Only counting null bytes towards valid code caves.
		{
			count++;
		}
		else
		{
			if(count > biggestCave)
			{
				biggestCave = count;
				bestLocation = i-count; //We want the beginning of this code cave, not the end of it.
				//printf("[+] Found another code cave of size: 0x%lx.\n", count);
			}
			count = 0;
		}
	}

	if(biggestCave != 0)
	{
		printf("[*] Largest code cave is 0x%lx bytes long at offset  0x%lx.\n", biggestCave, bestLocation);
		if (biggestCave < STUB_SIZE)
		{
			printf("[X] Biggest code cave found was 0x%lx bytes long, at least 0x%x bytes needed to inject stub.\n", biggestCave, STUB_SIZE);
		}
	}
	else
	{
		printf("[X] Could not find a single code cave.\n");
		return -1;
	}

	return bestLocation;
}

//Opens the target image. Returns a file pointer to the target image.
//Will cause program to exit on failure.
FILE* openImage(char* imageName)
{
	FILE* image = fopen(imageName, "r+");

	if(image == NULL)
	{
		printf("[X] Could not open file. Check the file name, and check it's permissions.\n");
		exit(EX_NOINPUT);
	}

	if(!isValidImage(image))
	{
		printf("[X] Image validation failed. Aborting.\n");
		exit(EX_DATAERR);
	}

	return image;
}

//Returns the offset at which the .shstrtab section is located.
//.shstrtab = section header string table
Elf64_Shdr getShstrtabSH(FILE* image)
{
	Elf64_Ehdr elfHeader;
	Elf64_Shdr sectionHeader;
	long shstrtabOffset;

	rewind(image);
	fread(&elfHeader, sizeof(elfHeader), 1, image);

	shstrtabOffset = elfHeader.e_shoff + (elfHeader.e_shentsize * elfHeader.e_shstrndx);
	fseek(image, shstrtabOffset, SEEK_SET);
	fread(&sectionHeader, sizeof(sectionHeader), 1, image);

	if(sectionHeader.sh_type != SHT_STRTAB)
	{
		printf("[X] Detected possible corruption. Expected section header type of 3 (SHT_STRTAB), found %d. Aborting.\n", sectionHeader.sh_type);
		exit(EX_DATAERR);
	}

	return sectionHeader;
}

//Obtains the .text section header.
Elf64_Shdr getTextSH(FILE* image)
{
	Elf64_Ehdr elfHeader;
	Elf64_Shdr textSH;
	Elf64_Shdr stringtabSH = getShstrtabSH(image);
	char names[stringtabSH.sh_size];

	rewind(image);
	fread(&elfHeader, sizeof(elfHeader), 1, image);

	fseek(image, stringtabSH.sh_offset, SEEK_SET);
	fread(&names, sizeof(names), 1, image);

	//Perform associative array lookup for .text
	fseek(image, elfHeader.e_shoff, SEEK_SET);
	for(int i = 0; i < elfHeader.e_shnum; i++)
	{
		fread(&textSH, sizeof(textSH), 1, image);
		if (strcmp(".text", names+textSH.sh_name) == 0)
		{
			break; //We've found the .text header at this point.
		}
	}

	return textSH;
}

//Encrypts the section based on the section header provided.
int encryptSection(Elf64_Shdr sectionHeader, FILE* image)
{
	char cryptobuf[sectionHeader.sh_size];

	fseek(image, sectionHeader.sh_offset, SEEK_SET);
	fread(&cryptobuf, sizeof(cryptobuf), 1, image);

	//If you are looking to swap out the cipher used, here is where you would do it.
	//You will also want switch the stub to match your cipher.
	for(int i = 0; i < sizeof(cryptobuf); i++)
	{
		cryptobuf[i] = cryptobuf[i] ^ XOR_BYTE; //Apply hardcore cryptography.
	}
	//End cipher section

	fseek(image, sectionHeader.sh_offset, SEEK_SET);
	int writes = fwrite(cryptobuf, sizeof(cryptobuf), 1, image);
	if (writes != 1)
	{
		printf("[X] fwrite failure during section encryption. Wrote %d objects. Expected 1.\n", writes);
		return 0;
	}

	return 1;
}

char* getShellcode(FILE* image)
{
	const char* stub =
	"\x49\xb8\xfe\xfe\xfe\xc0\x00\x00\x00\x00"	// movq r8, 0xC0FEFEFE	// "oldEntry". Location of target section. Same as .text vaddr given my use.
	"\x49\xc7\xc1\x55\x55\x55\x55"				// movq r9, 0x55555555	// Size of target section
	"\x49\x89\xd7"								// mov  r15, rdx		// Apparently we need to save rdx in order to exit smoothly. Don't ask me why.

																		// mprotect system call. Enable writing to specified section.
	"\x48\xc7\xc0\x0a\x00\x00\x00"				// movq rax, 0x0A		// System call number for mprotect
	"\x4c\x89\xc7"								// movq rdi, r8			// Vaddr of target region
	"\x48\x81\xe7\x00\xf0\xff\x00"				// and  rdi, 0xFFF000	// PGROUNDOWN required for mprotect's vaddr param to be page aligned.
	"\x4c\x89\xce"								// movq rsi, r9			// Size of section to mprotect
	"\x48\xc7\xc2\x07\x00\x00\x00"				// movq rdx, 0x07		// Set permission to request for target region, PROT_EXEC | PROC_WRITE | PROT_READ.
	"\x0f\x05"									// syscall				// Make the call. We aren't checking RAX to see if it worked :P

	"\x4d\x89\xc3"								// movq r11, r8			// Get a disposable copy of oldEntry
	"\x4d\x89\xc4"								// movq r12, r8			// Going to end of target section...
	"\x4d\x01\xcc"								// add  r12, r9			// Register is now pointing at the end of the target section

																		// Decrypt specified section
	"\x45\x8a\x2b"								// movb r13b, [r11]		// Get a byte
	"\x41\x80\xf5\x77"							// xor  r13b, 0x77		// The XOR-crypto byte in question
	"\x45\x88\x2b"								// movb [r11], r13b		// Write the byte back to where it came from
	"\x49\xff\xc3"								// inc r11				// Move to next byte
	"\x4d\x39\xe3"								// cmp r11, r12			// Set flags
	"\x0f\x8e\xea\xff\xff\xff"					// jle 0xfffffffffffffff0 // Jump back to the beginning of this paragraph if we haven't decrypted entire .text yet.

																		// Another mprotect system call. Disable writing to specified section to avoid suspicion.
	"\x48\xc7\xc0\x0a\x00\x00\x00"				// movq rax, 0x0A		// Set system call number for mprotect
	"\x4c\x89\xc7"								// movq rdi, r8			// Vaddr of target region
	"\x48\x81\xe7\x00\xf0\xff\x00"				// and rdi, 0xFFF000	// PGROUNDOWN required for mprotect's vaddr param to be page aligned.
	"\x4c\x89\xce"								// movq rsi, r9			// Size of region to mprotect
	"\x48\xc7\xc2\x05\x00\x00\x00"				// movq rdx, 0x05		// Set permission to request for target region, PROT_EXEC | PROT_READ.
	"\x0f\x05"									// syscall				// Make the call. Again, not checking RAX :P

	"\x4c\x89\xfa"								// mov rdx, r15			// Restore rdx to avoid explosions during exit.
	"\x41\xff\xe0";								// jmp r8				// Decryption is done, jump back to the original entrypoint.

	// Now get around to patching in the propper memorry addresses for the given executable.
	char* shellcode = (char*)calloc(1, STUB_SIZE);
	memcpy(shellcode, stub, STUB_SIZE);

	Elf64_Ehdr elfHeader;
	rewind(image);
	fread(&elfHeader, sizeof(elfHeader), 1, image);
	int oldEntry = elfHeader.e_entry;
	memcpy(&shellcode[2], &oldEntry, 4); //replace 0xC0FEFEFE with the old entrypoint
	printf("[*] Setting old entry point to 0x%x.\n", oldEntry);

	Elf64_Shdr textSH = getTextSH(image);
	int len = textSH.sh_size;
	memcpy(&shellcode[13], &len, 4); //replace 0x55555555

	memset(&shellcode[64], XOR_BYTE, 1); //replace 0x77 with byte to be XOR'd with.

	return shellcode;
}

//Make sure the cave you inject into is smaller then the shellcode.
void writeStub(FILE* image)
{
	Elf64_Ehdr elfHeader;
	int caveLocation = findCave(image);

	rewind(image);
	fread(&elfHeader, sizeof(elfHeader), 1, image);

	//write the stub
	char* stubBytes = getShellcode(image);
	fseek(image, caveLocation, SEEK_SET);
	fwrite(stubBytes, STUB_SIZE, 1, image);

	//Modify the ELF's entry point to point at the stub.
	rewind(image);
	fread(&elfHeader, sizeof(elfHeader), 1, image);
	if (elfHeader.e_entry < 0x400000) //OEP sanity checks. Is target ELF using the medium size memory layout?
	{
		printf("[X] Small original entry point detected. Crypter will likely fail during execution.\n");
	}
	else if (elfHeader.e_entry > 0x500000)
	{
		printf("[X] Large original entry point detected. Crypter will likely fail during execution.\n");
	}
	else
	{
		printf("[*] Entry point found near 0x400000.\n");
		elfHeader.e_entry = 0x400000 + caveLocation;
		printf("[*] Setting new entry point to 0x%lx.\n", elfHeader.e_entry);
		rewind(image);
		fwrite(&elfHeader, sizeof(elfHeader), 1, image);
	}
}

int main(int argc, char* argv[])
{
	FILE* image;

	if(argc < 2)
	{
		printf("[X] Usage: ./crypter <filename>\n");
		printf("[X] Terminating.\n");
		exit(EX_USAGE);
	}

	image = openImage(argv[1]);
	encryptSection(getTextSH(image), image);
	writeStub(image);
	fclose(image);

	printf("[+] Crypter has finished running.\n");

	return 0;
}
