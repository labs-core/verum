static inline void *verum_memcpy(void * restrict destination,
                                 const void * restrict source,
                                 uint32_t size)
{
    void *const ret = destination;

    uint8_t       *d   = (uint8_t *)destination;
    const uint8_t *s   = (const uint8_t *)source;
    uint32_t       len = size;

    while ((len > 0U) &&
           (((uint32_t)((uintptr_t)d) & VERUM_WORD_ALIGN) != 0U))
    {
        *d = *s;
        d++;
        s++;
        len--;
    }

    if (((uint32_t)((uintptr_t)s) & VERUM_WORD_ALIGN) == 0U)
    {
        uint32_t       *dw = (uint32_t *)__builtin_assume_aligned(d, VERUM_WORD_SIZE);
        const uint32_t *sw = (const uint32_t *)__builtin_assume_aligned(s, VERUM_WORD_SIZE);

        uint32_t wn = len / VERUM_WORD_SIZE;
        uint32_t wi = 0U;

        while (wn >= VERUM_UNROLL_FACTOR)
        {
            dw[wi + 0U] = sw[wi + 0U];
            dw[wi + 1U] = sw[wi + 1U];
            dw[wi + 2U] = sw[wi + 2U];
            dw[wi + 3U] = sw[wi + 3U];
            wi += VERUM_UNROLL_FACTOR;
            wn -= VERUM_UNROLL_FACTOR;
        }

        while (wn > 0U)
        {
            dw[wi] = sw[wi];
            wi++;
            wn--;
        }

        d   = (uint8_t *)&dw[wi];
        s   = (const uint8_t *)&sw[wi];
        len &= VERUM_WORD_ALIGN;
    }

    {
        uint32_t i;
        for (i = 0U; i < len; i++)
        {
            d[i] = s[i];
        }
    }

    return ret;
}