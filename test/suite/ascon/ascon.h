#ifndef TEST_ASCON_AEAD_H_
#define TEST_ASCON_AEAD_H_

int run_aead_tests(void);
int run_hash256_tests(void);
int run_xof128_tests(void);
int run_cxof128_tests(void);
#ifdef VERUM_STANDARD_FIPS_140_3_DEF
int run_fips1403_tests(void);
#endif /* VERUM_STANDARD_FIPS_140_3_DEF */

#endif /* TEST_ASCON_AEAD_H_ */
