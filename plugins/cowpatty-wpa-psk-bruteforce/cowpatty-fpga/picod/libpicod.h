int picoinit(char *[]);
int piconumcards(void);
int picomemread(int, unsigned long, void *, int);
int picoattribread(int, unsigned long, void *, int);
int picoioread(int, unsigned long, void *, int);
int picomemwrite(int, unsigned long, void *, int);
int picoattribwrite(int, unsigned long, void *, int);
int picoiowrite(int, unsigned long, void *, int);
int _picoread(int, int, unsigned long, unsigned char *, int);
int _picowrite(int, int, unsigned long, unsigned char *, int);
int picotrylock(int);
int picounlock(int);
int picoreboot(int, char *);
