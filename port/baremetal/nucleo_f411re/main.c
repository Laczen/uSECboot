#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include "usecboot.h"
#include "soft_sha256.h"
#include "root_pkey.h"

#ifndef container_of
#define container_of(ptr, type, member) ({ \
    const typeof(((type *)0)->member) * __mptr = (ptr); \
    (type *)((char *)__mptr - offsetof(type, member)); })
#endif

#define IMAGE1_BASE 0x00020000
#define IMAGE2_BASE 0x00040000
#define HMAC_KEY "\xab\x23\x45\x56"

#include <stdint.h>

#define PERIPH_BASE        0x40000000UL

#define AHB1PERIPH_BASE    (PERIPH_BASE + 0x00020000UL)
#define APB1PERIPH_BASE    (PERIPH_BASE + 0x00000000UL)

#define RCC_BASE           (AHB1PERIPH_BASE + 0x3800UL)
#define GPIOA_BASE         (AHB1PERIPH_BASE + 0x0000UL)
#define USART2_BASE        (APB1PERIPH_BASE + 0x4400UL)

#define RCC_AHB1ENR        (*(volatile unsigned long *)(RCC_BASE + 0x30))
#define RCC_APB1ENR        (*(volatile unsigned long *)(RCC_BASE + 0x40))

#define GPIOA_MODER        (*(volatile unsigned long *)(GPIOA_BASE + 0x00))
#define GPIOA_AFRL         (*(volatile unsigned long *)(GPIOA_BASE + 0x20))

#define USART2_SR          (*(volatile unsigned long *)(USART2_BASE + 0x00))
#define USART2_DR          (*(volatile unsigned long *)(USART2_BASE + 0x04))
#define USART2_BRR         (*(volatile unsigned long *)(USART2_BASE + 0x08))
#define USART2_CR1         (*(volatile unsigned long *)(USART2_BASE + 0x0C))
#define USART2_CR2         (*(volatile unsigned long *)(USART2_BASE + 0x10))
#define USART2_CR3         (*(volatile unsigned long *)(USART2_BASE + 0x14))

#define GPIOA_ODR          (*(volatile uint32_t*)(GPIOA_BASE + 0x14))

#define SCS_BASE        (0xE000E000UL)
#define DWT_BASE        (SCS_BASE + 0x1000UL)
#define DEMCR           (*(volatile uint32_t *)(SCS_BASE + 0x0DFCUL))
#define DWT_CTRL        (*(volatile uint32_t *)(DWT_BASE + 0x0000UL))
#define DWT_CYCCNT      (*(volatile uint32_t *)(DWT_BASE + 0x0004UL))

// RCC registers (STM32F4 specific, but we'll read them directly)
#define RCC_CR      (*(volatile uint32_t *)(RCC_BASE + 0x00UL))
#define RCC_CFGR    (*(volatile uint32_t *)(RCC_BASE + 0x08UL))
#define RCC_PLLCFGR (*(volatile uint32_t *)(RCC_BASE + 0x04UL))

// Register bit definitions
#define RCC_CR_HSION      (1UL << 0U)
#define RCC_CR_HSIRDY     (1UL << 1U)
#define RCC_CR_MSION      (1UL << 0U)  // Note: MSI shares same bit position in different register view
#define RCC_CR_MSIRDY     (1UL << 1U)
#define RCC_CR_PLLON      (1UL << 24U)
#define RCC_CR_PLLRDY     (1UL << 25U)

#define RCC_CFGR_SWS_Pos  (2U)
#define RCC_CFGR_SWS_Msk  (0x3UL << RCC_CFGR_SWS_Pos)
#define RCC_CFGR_SWS      RCC_CFGR_SWS_Msk

#define RCC_CR_MSIRANGE_Pos (4U)
#define RCC_CR_MSIRANGE_Msk (0xFUL << RCC_CR_MSIRANGE_Pos)

#define DEMCR_TRCENA      (1UL << 24U)
#define DWT_CTRL_CYCCNTENA (1UL << 0U)

struct soft_sha256_ctx hash_ctx;

struct myslot {
	uint32_t offset;
	struct soft_sha256_ctx *hctx;
	struct usecboot_slot slot;
};

void led_set(void)
{
	GPIOA_ODR |= (1 << 5);
}

void led_reset(void)
{
	GPIOA_ODR &= ~(1 << 5);
}

void *memcpy(void *dst, const void *src, size_t len);
void uart_puts(const char *str);

int prep(const struct usecboot_slot *slot)
{
	uint8_t msg[2048];
	uint8_t hash[32];
	size_t len = 0x70000;
	uint8_t off = 0;
	int rc;
	struct soft_sha256_ctx ctx;

	led_set();
	soft_sha256_init(&ctx);
	while (len != 0) {
		const size_t rdlen = len < sizeof(msg) ? len : sizeof(msg);

		rc = slot->api->read(slot, off, (void *)msg, rdlen);
		if (rc != USECBOOTERR_NONE) {
			break;
		}

		soft_sha256_update(&ctx, msg, rdlen);
		off += rdlen;
		len -= rdlen;
	}

	soft_sha256_final (&ctx, hash);
	led_reset();
	return USECBOOTERR_NONE;
}

int read(const struct usecboot_slot *slot, uint32_t start, void *data,
	 size_t len)
{
	const struct myslot *myslot = container_of(slot, struct myslot, slot);

	void *flash_ptr = (void *)(myslot->offset + start);

	memcpy(data, flash_ptr, len);
	return USECBOOTERR_NONE;
}

void boot(const struct usecboot_slot *slot, uint32_t ioff)
{
	const struct myslot *myslot = container_of(slot, struct myslot, slot);
	const uint32_t app_address = myslot->offset + ioff;
    	const uint32_t initial_sp = *(volatile uint32_t*)app_address;
	const uint32_t reset_handler = *(volatile uint32_t*)(app_address + 4);

	__asm volatile ("dsb; isb");
	__asm volatile ("cpsid i");

	__asm volatile (
		"msr msp, %0\n"
		"bx %1\n"
		:
		: "r" (initial_sp), "r" (reset_handler)
    	);
}

void clean(const struct usecboot_slot *slot)
{
	(void)slot;
}

void hash_init(const struct usecboot_slot *slot)
{
	const struct myslot *myslot = container_of(slot, struct myslot, slot);

	soft_sha256_init(myslot->hctx);
}

void hash_update(const struct usecboot_slot *slot, const void *msg,
		   size_t msglen)
{
	const struct myslot *myslot = container_of(slot, struct myslot, slot);

	soft_sha256_update(myslot->hctx, msg, msglen);
}

int hash_cmp(const struct usecboot_slot *slot, const void *hash,
	     size_t hashlen)
{
	if (hashlen != SOFT_SHA256_DIGESTSIZE) {
		return 1;
	}

	const struct myslot *myslot = container_of(slot, struct myslot, slot);
	const uint8_t *p = (const uint8_t *)hash;
	uint8_t digest[SOFT_SHA256_DIGESTSIZE];
	int rv = 0;

	soft_sha256_final(myslot->hctx, (void *)digest);
	for (size_t i = 0; i < sizeof(digest); i++) {
		rv |= digest[i] ^ p[i];
		digest[i] = 0U;
	}

	return rv == 0U ? 0 : 1;
}

const struct usecboot_slotapi slotapi = {
	.read = read,
	.prep = prep,
	.boot = boot,
	.clean = clean,
	.hash_init = hash_init,
	.hash_update = hash_update,
	.hash_cmp = hash_cmp,
};

const struct myslot myslot[2] = {
	{
		.offset = IMAGE1_BASE,
		.hctx = &hash_ctx,
		.slot.size = 2<<16,
		.slot.api = &slotapi,
	},{
		.offset = IMAGE2_BASE,
		.hctx = &hash_ctx,
		.slot.size = 2<<16,
		.slot.api = &slotapi,
	},
};

const struct usecboot_slot *usecboot_get_slot(uint8_t idx)
{
	if (idx >= sizeof(myslot)/sizeof(myslot[0])) {
		return NULL;
	}

	return &myslot[idx].slot;
}

int usecboot_get_rejected_pubkey(uint32_t idx, uint8_t *pubkey, size_t len)
{
	(void)idx;
	(void)pubkey;
	(void)len;
	return -USECBOOTERR_ENOENT;
}

int usecboot_get_rootpkey(void *pkey, size_t len)
{
	const char *rootpkey = USECBOOT_ROOTPKEY;
	uint8_t *pk = (uint8_t *)pkey;

	if (len != sizeof(USECBOOT_ROOTPKEY) - 1) {
		return -USECBOOTERR_EINVAL;
	}

	memcpy(pk, rootpkey, len);
	return 0;
}

void led_init(void);
void uart_init(void);

int main(void)
{
	led_init();
	led_reset();
	uart_init();
	usecboot_boot();
    	return 0;
}

/* provide a minimal memcpy, memset and some other routines */
void *memcpy(void *dst, const void *src, size_t len)
{
	uint8_t *dst8 = (uint8_t *)dst;
	const uint8_t *src8 = (const uint8_t *)src;

	for (size_t i = 0; i < len; i++) {
		dst8[i] = src8[i];
	}

	return dst;
}

void led_init(void)
{
	// Setup LED
	RCC_AHB1ENR |= (1 << 0);
	GPIOA_MODER |= (1 << 10);
}

void uart_clear_dr(void)
{
	// Read the DR register to clear any stale data
	volatile uint32_t dummy = USART2_DR;
	(void)dummy; // Prevent unused variable warning
}

void uart_init(void) {
	// Enable clocks
	RCC_AHB1ENR |= (1 << 0);
	RCC_APB1ENR |= (1 << 17);

	// Configure GPIO
	GPIOA_MODER &= ~((3 << (2*2)) | (3 << (3*2)));
	GPIOA_MODER |=  ((2 << (2*2)) | (2 << (3*2)));
	GPIOA_AFRL &= ~((0xF << (2*4)) | (0xF << (3*4)));
	GPIOA_AFRL |=  ((7 << (2*4)) | (7 << (3*4)));

	// Clear any stale data from DR
	uart_clear_dr();

	// Set baud rate
	USART2_BRR = 0x08B;

	// Clear any pending status flags by reading SR
	volatile uint32_t status = USART2_SR;
	(void)status;

	USART2_CR1 |= (1 << 13);  // UE first
	for(volatile int i = 0; i < 1000; i++);  // Wait for baud rate to stabilize

	// NOW enable transmitter
	USART2_CR1 |= (1 << 3) | (1 << 2);  // TE + RE
}

void uart_putc(char c)
{
	while (!(USART2_SR & (1 << 7)));  // Wait for TXE
	USART2_DR = c;
}

void uart_puts(const char *str) {
	while (*str) {
		uart_putc(*str++);
	}
}

void uart_puthex(uint32_t val) {
    const char hex_chars[] = "0123456789ABCDEF";

    uart_putc('0');
    uart_putc('x');

    for (int i = 28; i >= 0; i -= 4) {
        uart_putc(hex_chars[(val >> i) & 0xF]);
    }
}

void uart_putdec(uint32_t val) {
    char buffer[10];
    char *p = buffer + 9;
    *p = '\0';

    do {
        *--p = '0' + (val % 10);
        val /= 10;
    } while (val > 0);

    uart_puts(p);
}

void uart_vprintf(const char *fmt, va_list args)
{
	while (*fmt) {
		if (*fmt == '%') {
	    	fmt++;
	    	switch (*fmt) {
	        case 'd': {
        	        uint32_t val = va_arg(args, uint32_t);
                	uart_putdec(val);
                    	break;
                }
                case 'x': {
                    	uint32_t val = va_arg(args, uint32_t);
                    	uart_puthex(val);
			break;
                }
                case 's': {
			char *str = va_arg(args, char*);
			uart_puts(str);
			break;
                }
                case 'c': {
			char c = (char)va_arg(args, int);
                	uart_putc(c);
                	break;
                }
                default:
			uart_putc(*fmt);
            }
        } else {
        	uart_putc(*fmt);
        }
        fmt++;
    }
}

void uart_printf(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	uart_vprintf(fmt, args);
	va_end(args);
}

void usecboot_log(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	uart_vprintf(fmt, args);
	va_end(args);
}