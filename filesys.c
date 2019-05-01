#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include "filesys.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <limits.h>

static int filesys_inited = 0;

// ---- Queue implementation taken from GeeksforGeeks ----

// A structure to represent a queue 
struct Queue 
{ 
    int front, rear, size; 
    unsigned capacity; 
    unsigned char** array; 
}; 
  
// function to create a queue of given capacity.  
// It initializes size of queue as 0 
struct Queue* createQueue(unsigned capacity) 
{ 
    struct Queue* queue = (struct Queue*) malloc(sizeof(struct Queue)); 
    queue->capacity = capacity; 
    queue->front = queue->size = 0;  
    queue->rear = capacity - 1;  // This is important, see the enqueue 
    queue->array = (unsigned char**) malloc(queue->capacity * sizeof(unsigned char*)); 
    return queue; 
} 
  
// Queue is full when size becomes equal to the capacity  
int isFull(struct Queue* queue) 
{  return (queue->size == queue->capacity);  } 
  
// Queue is empty when size is 0 
int isEmpty(struct Queue* queue) 
{  return (queue->size == 0); } 
  
// Function to add an item to the queue.   
// It changes rear and size 
void enqueue(struct Queue* queue, unsigned char* item) 
{ 
    if (isFull(queue)) 
        return; 
    queue->rear = (queue->rear + 1)%queue->capacity; 
    queue->array[queue->rear] = item; 
    queue->size = queue->size + 1; 
} 
  
// Function to remove an item from queue.  
// It changes front and size 
unsigned char* dequeue(struct Queue* queue) 
{
    unsigned char* item = queue->array[queue->front]; 
    queue->front = (queue->front + 1)%queue->capacity; 
    queue->size = queue->size - 1; 
    return item; 
}

/* returns 20 bytes unique hash of the buffer (buf) of length (len)
 * in input array sha1.
 */
void get_sha1_hash (const void *buf, int len, const void *sha1)
{
	SHA1 ((unsigned char*)buf, len, (unsigned char*)sha1);
}

void delete_line (int lineNo)
{
	FILE *fptr1, *fptr2;
	fptr1 = fopen("secure.txt", "r");
	fptr2 = fopen("temp.txt", "w");

	int ctr = 1;
	char str[256];
	while(!feof(fptr1))
	{
		strcpy(str, "\0");
		fgets(str, 256, fptr1);
		if(!feof(fptr1))
		{
			ctr++;
			if (ctr != lineNo+1)
			{
				fprintf(fptr2, "%s", str);
			}
		}
	}

	fclose(fptr1);
	fclose(fptr2);
	remove("secure.txt");
	rename("temp.txt", "secure.txt");
}

int check_integrity (const char* pathname, unsigned char humanreadable[40])
{
	FILE *fptr = fopen("secure.txt", "r");
	char* line = NULL;
	size_t buffsize = 0;
	size_t characters;
	int lineNo = 0;
	while((characters = getline(&line, &buffsize, fptr)) != -1)
	{

		lineNo++;
		line = strtok(line, "\n");
		char* token = strtok(line, " ");
		if (strcmp(token, pathname) == 0)
		{
			token = strtok(NULL, " ");
			fclose(fptr);
			if (strcmp(token, (char*) humanreadable) == 0)
			{
				return 1;
			}
			else
			{
				// delete_line(lineNo);
				return 0;
			}
		}
	}
	free(line);
	fclose(fptr);
	return -1;
}

unsigned char* generateHash (unsigned char *humanreadable, const char *pathname, int flags, mode_t mode)
{
	int fd = open(pathname, flags, mode);
	char* dataBlocks[128000];
	read(fd, dataBlocks, 128000);
	close(fd);
	unsigned char finalRootHash[20];
	get_sha1_hash(dataBlocks, 128000, finalRootHash);

	// // fetching all the datablocks
	// char* dataBlocks[2000][64];

	// for (int i = 0; i < 2000; ++i)
	// {
	// 	lseek(fd, i*64, SEEK_SET);
	// 	read(fd, dataBlocks[i], 64);
	// }

	// close(fd);

	// // converting all the datablocks into hashes and storing in an array
	// unsigned char sha1[2000][20];
	// for (int i = 0; i < 2000; ++i)
	// {
	// 	get_sha1_hash(dataBlocks[i], 64, sha1[i]);
	// }

	// struct Queue* queue = createQueue(2000);
	// for (int i = 0; i < 2000; ++i)
	// {
	// 	enqueue(queue, sha1[i]);
	// }
	
	// unsigned char finalRootHash[20];

	// while (1)
	// {
	// 	unsigned char* first = dequeue(queue);
	// 	unsigned char* second = dequeue(queue);

	// 	int firstSize = strlen((const char*) first);
	// 	int secondSize = strlen((const char*) second);

	// 	unsigned char* concat = malloc(firstSize + secondSize + 1);

	// 	memcpy(concat, first, firstSize);
	// 	strcat((char*) concat, (char*) second);

	// 	unsigned char concatHash[20];
	// 	get_sha1_hash(concat, 40, concatHash);

	// 	if (isEmpty(queue))
	// 	{
	// 		memcpy(finalRootHash, concatHash, 20);
	// 		free(queue);
	// 		break;
	// 	}

	// 	enqueue(queue, concatHash);
	// }

	for (int i = 0; i < 20; i++)
	{
		sprintf((char*)&(humanreadable[i*2]), "%02x", finalRootHash[i]);
	}

	return humanreadable;
}

void append_to_secure (const char* pathname, unsigned char humanreadable[40])
{
	int sfd = open("secure.txt", O_CREAT|O_APPEND|O_WRONLY, 0644);
	write(sfd, pathname, strlen(pathname));
	write(sfd, " ", 1);
	write(sfd, humanreadable, 40);
	write(sfd, "\n", 1);
	close(sfd);
}

/* Build an in-memory Merkle tree for the file.
 * Compare the integrity of file with respect to
 * root hash stored in secure.txt. If the file
 * doesn't exist, create an entry in secure.txt.
 * If an existing file is going to be truncated
 * update the hash in secure.txt.
 * returns -1 on failing the integrity check.
 */
int s_open (const char *pathname, int flags, mode_t mode)
{
	unsigned char arr[40];
	unsigned char* humanreadable = generateHash(arr, pathname, flags, mode);

	int integrity = check_integrity(pathname, humanreadable);
	// printf("INTEGRITY = %d", integrity);
	if (integrity == 1) // file passes integrity check
	{
		return open (pathname, flags, mode);
	}
	else if (integrity == 0) // file has been modified
	{
		append_to_secure(pathname, humanreadable);
		return -1;
	}
	else if (integrity == -1) // file does not exist
	{
		append_to_secure(pathname, humanreadable);
		return open (pathname, flags, mode);
	}

	assert (filesys_inited);
	return open (pathname, flags, mode);
}

/* SEEK_END should always return the file size 
 * updated through the secure file system APIs.
 */
int s_lseek (int fd, long offset, int whence)
{
	assert (filesys_inited);
	return lseek (fd, offset, SEEK_SET);
}

/* read the blocks that needs to be updated
 * check the integrity of the blocks
 * modify the blocks
 * update the in-memory Merkle tree and root in secure.txt
 * returns -1 on failing the integrity check.
 */

ssize_t s_write (int fd, const void *buf, size_t count)
{
	// FILE* fptr = fopen("secure.txt", "r");
	// char c;
	// c = fgetc(fptr);
	// while (c != EOF)
	// {
	// 	printf("%c", c);
	// 	c = fgetc(fptr);
	// }
	// fclose(fptr);

	struct stat s;
	char temp[100];
	sprintf(temp, "/proc/self/fd/%d", fd);
	lstat(temp, &s);
	char pathname[s.st_size+1];
	readlink(temp, pathname, s.st_size+1);

	char* filename;
	char* ptr = strtok(pathname, "/");
	while(ptr!=NULL)
	{
		filename = ptr;
		ptr = strtok(NULL, "/");
	}

	unsigned char arr[40];
	unsigned char* humanreadable = generateHash(arr, filename, O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR);

	int integrity = check_integrity(filename, humanreadable);
	if (integrity == 0 || integrity == -1)
	{
		return -1;
	}
	assert (filesys_inited);
	return write (fd, buf, count);
}

/* check the integrity of blocks containing the 
 * requested data.
 * returns -1 on failing the integrity check.
 */
ssize_t s_read (int fd, void *buf, size_t count)
{
	struct stat s;
	char temp[100];
	sprintf(temp, "/proc/self/fd/%d", fd);
	lstat(temp, &s);
	char pathname[s.st_size+1];
	readlink(temp, pathname, s.st_size+1);

	char* filename;
	char* ptr = strtok(pathname, "/");
	while(ptr!=NULL)
	{
		filename = ptr;
		ptr = strtok(NULL, "/");
	}

	unsigned char arr[40];
	unsigned char* humanreadable = generateHash(arr, filename, O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR);

	int integrity = check_integrity(filename, humanreadable);
	if (integrity == 0 || integrity == 0)
	{
		return -1;
	}

	assert (filesys_inited);
	return read (fd, buf, count);
}

/* destroy the in-memory Merkle tree */
int s_close (int fd)
{
	assert (filesys_inited);
	return close (fd);
}

/* Check the integrity of all files in secure.txt
 * remove the non-existent files from secure.txt
 * returns 1, if an existing file is tampered
 * return 0 on successful initialization
 */
int filesys_init (void)
{
	if (access("secure.txt", F_OK) == -1) {
		fclose(fopen("secure.txt", "w"));
	}

	FILE *fptr = fopen("secure.txt", "r");
	
	char* line = NULL;
	size_t buffsize = 0;
	size_t characters;
	
	int lineNo = 0;

	int delete_files[1000];
	int i = 0;

	while((characters = getline(&line, &buffsize, fptr)) != -1)
	{
		lineNo++;
		line = strtok(line, "\n");
		char* filename = strtok(line, " ");

		if (access(filename, F_OK) == -1) {
			delete_files[i++] = lineNo;
		}
	}

	i = 0;

	while (delete_files[i] != 0)
	{
		fptr = fopen("secure.txt", "r");
		delete_line(delete_files[i++]);
	}

	int integrity_compromised = 0;

	while((characters = getline(&line, &buffsize, fptr)) != -1)
	{
		lineNo++;
		line = strtok(line, "\n");
		char* filename = strtok(line, " ");

		char* hash = strtok(NULL, " ");

		unsigned char arr[40];
		unsigned char *humanreadable = generateHash(arr, filename, O_RDONLY, 0);

		if (strcmp(hash, (char*) humanreadable) != 0)
		{
			integrity_compromised = 1;
		}
	}
	free(line);
	fclose(fptr);
	
	filesys_inited = 1;
	return integrity_compromised;
}
