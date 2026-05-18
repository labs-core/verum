#ifndef UNITY_CONFIG_H
#define UNITY_CONFIG_H
 
extern void runner_putchar(int c);
 
#define UNITY_OUTPUT_CHAR(a)    runner_putchar(a)
#define UNITY_OUTPUT_FLUSH()    /* nothing – we flush each line ourselves */
 
#endif /* UNITY_CONFIG_H */
 
