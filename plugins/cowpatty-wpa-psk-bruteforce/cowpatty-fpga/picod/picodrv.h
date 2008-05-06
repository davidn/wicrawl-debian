int piconumcards(void);
void picoopen(void);
int picoread(unsigned long, void *, unsigned long);
int picowrite(unsigned long, void *, unsigned long);
void picoclose(void);
int picotrylock(int);
int picounlock(int);
int picoreboot(char *);
