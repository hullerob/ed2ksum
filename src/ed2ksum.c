/* See LICENSE file for copyright and license details. */

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <openssl/md4.h>

const char VERSION[] = "2";

#define CHUNK_SIZE (9500*1024)
#define BUFF_SIZE (8*1024)

unsigned char buff[BUFF_SIZE];
unsigned char md[MD4_DIGEST_LENGTH];
uint64_t file_length;

void help(void);
void version(void);
void usage(void);

int ed2k (int fd)
{
  int length;
  int chunknum, chunklength, curlength;
  MD4_CTX root;
  MD4_CTX chunk;
  MD4_Init(&root);
  MD4_Init(&chunk);
  chunknum = 0;
  chunklength = 0;
  file_length = 0;
  while((length = read(fd, buff, BUFF_SIZE)) > 0)
  {
    file_length += length;
    if (length + chunklength > CHUNK_SIZE)
    {
      curlength = CHUNK_SIZE - chunklength;
      length = length - curlength;
    }
    else
    {
      curlength = length;
      length = 0;
    }
    MD4_Update(&chunk, buff, curlength);
    chunklength += curlength;
    if (chunklength == CHUNK_SIZE)
    {
      MD4_Final(md, &chunk);
      MD4_Init(&chunk);
      MD4_Update(&root, md, MD4_DIGEST_LENGTH);
      MD4_Update(&chunk, &buff[curlength], length);
      chunklength = length;
      chunknum ++;
    }
  }
  if (length < 0)
  {
    return -1;
  }
  if (chunknum > 0)
  {
    if (chunklength > 0)
    {
      MD4_Final(md, &chunk);
      MD4_Update(&root, md, MD4_DIGEST_LENGTH);
    }
    MD4_Final(md, &root);
  }
  else
    MD4_Final(md, &chunk);
  return 0;
}

int main (int argc, char **argv)
{
  int print_raw = 0;
  int i, j;
  int fd;
  if (argc < 2)
    usage();
  for (i = 1; i < argc; i++)
  {
    if (strcmp(argv[i], "--") == 0)
    {
      i++;
      break;
    }
    if (argv[i][0] != '-')
      break;
    if (argv[i][1] == '\0')
      break;
    switch (argv[i][1])
    {
    case 'h':
      help();
      exit(0);
      break;
    case 'V':
      version();
      exit(0);
      break;
    case 'r':
      print_raw = 1;
      break;
    default:
      usage();
      exit(1);
      break;
    }
  }
  for (; i < argc; i++)
  {
    if (strcmp(argv[i], "-") == 0)
      fd = 0;
    else
      fd = open(argv[i], O_RDONLY);
    if (fd < 0)
    {
      fprintf(stderr, "error while opening file '%s': %s\n", argv[i], strerror(errno));
      continue;
    }
    if (ed2k(fd) < 0)
    {
      fprintf(stderr, "error while reading file '%s': %s\n", argv[i], strerror(errno));
    }
    else
    {
      if (!print_raw)
        printf("ed2k://|file|%s|%llu|", basename(argv[i]), file_length);
      for (j = 0; j < MD4_DIGEST_LENGTH; j++)
      {
        printf("%02x", md[j]);
      }
      if (!print_raw)
        printf("|\n");
      else
        printf("\n");
    }
    if (fd > 0)
      close(fd);
  }
  return 0;
}

void help(void)
{
  printf("ed2ksum - compute and print ed2k links for files\n\n"
    "options:\n"
    "  -h         print this message\n"
    "  -V         print version information\n"
    "  -r         print only hash value\n");
}

void version(void)
{
  printf("ed2ksum version %s\n", VERSION);
}

void usage(void)
{
  printf("usage: `ed2ksum [FILE] ...' or `-h'\n");
}
